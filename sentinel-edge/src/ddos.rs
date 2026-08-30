//! DDoS Detection Module + Global Traffic Monitor (WI-11)
//!
//! Detects various DDoS attack patterns:
//! - Volumetric attacks (high request rate per IP)
//! - Slow loris attacks (connection exhaustion)
//! - Application layer attacks (targeted endpoints)
//!
//! Global Defense Mode:
//! - Traffic baseline calculation (5-min sliding window)
//! - Spike detection: current_rps > baseline + 3 × stddev
//! - Anti-flash-crowd gate: unique_ip_ratio discriminates real users from DDoS
//!   - ratio > 0.7 → flash crowd (real traffic), do NOT activate defense
//!   - ratio < 0.3 → DDoS (few IPs, many requests), FULL defense mode
//!   - 0.3–0.7 → grey zone, SOFT defense mode (challenge only, no aggressive rate limit)
//! - Defense mode effects: aggressive challenge, halved rate limits, extended micro-cache TTL
//! - Auto-deactivation after 5 min below threshold

use sentinel_core::sharded_lru::ShardedLru;
use sentinel_core::Request;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use parking_lot::{Mutex, RwLock};
use std::time::{Duration, Instant};

/// Types of DDoS patterns detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DDoSPattern {
    /// High volume of requests
    Volumetric,
    /// Slow connection attacks
    SlowLoris,
    /// Application layer attacks targeting specific endpoints
    ApplicationLayer,
}

/// Defense mode level
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DefenseLevel {
    /// Normal operation
    Off,
    /// Soft defense: challenges only, no aggressive rate limiting
    Soft,
    /// Full defense: aggressive challenges + halved rate limits + extended cache
    Full,
}

/// Defense mode status (exposed via /defense-mode API)
#[derive(Debug, Clone, serde::Serialize)]
pub struct DefenseModeStatus {
    /// Whether defense mode is active
    pub active: bool,
    /// Defense level
    pub level: DefenseLevel,
    /// When defense mode was activated (seconds ago, 0 if inactive)
    pub active_for_secs: u64,
    /// Current requests per second
    pub current_rps: f64,
    /// Baseline requests per second (5-min average)
    pub baseline_rps: f64,
    /// Baseline standard deviation
    pub baseline_stddev: f64,
    /// Unique IP ratio in last 60s (0.0–1.0)
    pub unique_ip_ratio: f64,
    /// Total tracked IPs
    pub tracked_ips: usize,
}

/// Request tracking for DDoS detection
struct RequestTracker {
    /// Recent request timestamps
    timestamps: VecDeque<Instant>,
    /// Endpoints hit
    endpoints: VecDeque<String>,
    /// Last active time
    last_active: Instant,
}

impl RequestTracker {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::with_capacity(1000),
            endpoints: VecDeque::with_capacity(100),
            last_active: Instant::now(),
        }
    }

    fn record(&mut self, path: &str) {
        let now = Instant::now();
        self.timestamps.push_back(now);
        self.endpoints.push_back(path.to_string());
        self.last_active = now;

        // Keep only last 10 seconds of data
        let cutoff = now - Duration::from_secs(10);
        while self.timestamps.front().map(|&t| t < cutoff).unwrap_or(false) {
            self.timestamps.pop_front();
        }
        // Cap HARD indipendente dal RATE (EL1-B): senza, un flood a 10k rps farebbe
        // crescere il deque a rate×finestra (100k Instant/IP) prima che scadano = OOM.
        while self.timestamps.len() > MAX_TIMESTAMPS_PER_TRACKER {
            self.timestamps.pop_front();
        }

        // Keep only last 100 endpoints
        while self.endpoints.len() > 100 {
            self.endpoints.pop_front();
        }
    }

    fn requests_per_second(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }

        let now = Instant::now();
        let window = Duration::from_secs(1);
        let count = self.timestamps.iter().filter(|&&t| now - t < window).count();
        count as f64
    }

    fn requests_last_10s(&self) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(10);
        self.timestamps.iter().filter(|&&t| now - t < window).count()
    }

    fn unique_endpoints(&self) -> usize {
        let mut unique: HashSet<&str> = HashSet::new();
        for ep in &self.endpoints {
            unique.insert(ep.as_str());
        }
        unique.len()
    }

    fn is_stale(&self) -> bool {
        self.last_active.elapsed() > Duration::from_secs(60)
    }
}

/// Per-second traffic counter for baseline calculation
#[derive(Debug, Clone, Copy)]
struct SecondBucket {
    /// Requests in this second
    count: u64,
    /// Timestamp
    timestamp: Instant,
}

/// Global Traffic Monitor (WI-11)
///
/// Calculates traffic baseline over 5-minute sliding window and detects
/// anomalous spikes that indicate DDoS attacks vs legitimate flash crowds.
struct GlobalTrafficMonitor {
    /// Per-second buckets (circular buffer, 300 entries = 5 min)
    second_buckets: RwLock<VecDeque<SecondBucket>>,
    /// Unique IPs seen in last 60s (for flash-crowd gate)
    recent_ips: RwLock<VecDeque<(Instant, IpAddr)>>,
    /// Total requests in last 60s (for unique IP ratio)
    recent_request_count: AtomicU64,
    /// Computed baseline RPS
    baseline_rps: RwLock<f64>,
    /// Computed baseline stddev
    baseline_stddev: RwLock<f64>,
    /// Defense mode state
    defense_level: RwLock<DefenseLevel>,
    /// Defense mode active flag (atomic for fast check)
    defense_active: AtomicBool,
    /// When defense mode was activated
    defense_since: RwLock<Option<Instant>>,
    /// Last baseline recalculation
    last_baseline_calc: RwLock<Instant>,
}

impl GlobalTrafficMonitor {
    fn new() -> Self {
        Self {
            second_buckets: RwLock::new(VecDeque::with_capacity(300)),
            recent_ips: RwLock::new(VecDeque::with_capacity(100_000)),
            recent_request_count: AtomicU64::new(0),
            baseline_rps: RwLock::new(10.0), // Minimum baseline
            baseline_stddev: RwLock::new(5.0),
            defense_level: RwLock::new(DefenseLevel::Off),
            defense_active: AtomicBool::new(false),
            defense_since: RwLock::new(None),
            last_baseline_calc: RwLock::new(Instant::now()),
        }
    }

    /// Record a request (called on every incoming request)
    fn record(&self, ip: IpAddr) {
        let now = Instant::now();

        // Update per-second bucket
        {
            let mut buckets = self.second_buckets.write();
            if let Some(last) = buckets.back_mut() {
                if now.duration_since(last.timestamp) < Duration::from_secs(1) {
                    last.count += 1;
                } else {
                    buckets.push_back(SecondBucket { count: 1, timestamp: now });
                }
            } else {
                buckets.push_back(SecondBucket { count: 1, timestamp: now });
            }

            // Prune old buckets (keep 5 min)
            let cutoff = now - Duration::from_secs(300);
            while buckets.front().map(|b| b.timestamp < cutoff).unwrap_or(false) {
                buckets.pop_front();
            }
        }

        // Track unique IPs (last 60s)
        {
            let mut ips = self.recent_ips.write();
            ips.push_back((now, ip));
            self.recent_request_count.fetch_add(1, Ordering::Relaxed);

            // Prune old entries
            let cutoff = now - Duration::from_secs(60);
            while ips.front().map(|(t, _)| *t < cutoff).unwrap_or(false) {
                ips.pop_front();
                self.recent_request_count.fetch_sub(1, Ordering::Relaxed);
            }

            // Hard limit to prevent memory explosion under DDoS
            while ips.len() > 100_000 {
                ips.pop_front();
                self.recent_request_count.fetch_sub(1, Ordering::Relaxed);
            }
        }

        // Recalculate baseline every 10 seconds
        {
            let should_recalc = {
                let last = self.last_baseline_calc.read();
                now.duration_since(*last) > Duration::from_secs(10)
            };

            if should_recalc {
                self.recalculate_baseline();
                *self.last_baseline_calc.write() = now;
                self.evaluate_defense_mode();
            }
        }
    }

    /// Recalculate baseline RPS and stddev from 5-minute window
    fn recalculate_baseline(&self) {
        let buckets = self.second_buckets.read();
        if buckets.len() < 10 {
            return; // Not enough data
        }

        let rps_values: Vec<f64> = buckets.iter().map(|b| b.count as f64).collect();
        let n = rps_values.len() as f64;

        let mean = rps_values.iter().sum::<f64>() / n;
        let variance = rps_values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();

        // Enforce minimum baseline (prevents false positives at very low traffic)
        let effective_mean = mean.max(10.0);

        *self.baseline_rps.write() = effective_mean;
        *self.baseline_stddev.write() = stddev.max(1.0);
    }

    /// Evaluate whether to activate/deactivate defense mode
    fn evaluate_defense_mode(&self) {
        let current_rps = self.current_rps();
        let baseline = *self.baseline_rps.read();
        let stddev = *self.baseline_stddev.read();

        let threshold = baseline + 3.0 * stddev;

        // Check if traffic spike is happening
        if current_rps > threshold {
            // Anti-flash-crowd gate: check unique IP ratio
            let ratio = self.unique_ip_ratio();

            if ratio > 0.7 {
                // Probably real traffic (many different IPs = real users)
                // Do NOT activate defense mode, just log warning
                tracing::info!(
                    current_rps = current_rps,
                    baseline = baseline,
                    threshold = threshold,
                    unique_ip_ratio = ratio,
                    "Traffic spike detected but unique_ip_ratio > 0.7 — likely flash crowd, not DDoS"
                );

                // Deactivate if currently in defense mode (flash crowd shouldn't be blocked)
                if self.defense_active.load(Ordering::Relaxed) {
                    self.deactivate_defense();
                }
            } else if ratio < 0.3 {
                // Probably DDoS (few IPs generating many requests)
                self.activate_defense(DefenseLevel::Full);
                tracing::warn!(
                    current_rps = current_rps,
                    baseline = baseline,
                    threshold = threshold,
                    unique_ip_ratio = ratio,
                    "DEFENSE MODE FULL: DDoS detected (low unique IP ratio)"
                );
            } else {
                // Grey zone — soft defense (challenges only, no aggressive rate limiting)
                self.activate_defense(DefenseLevel::Soft);
                tracing::warn!(
                    current_rps = current_rps,
                    baseline = baseline,
                    threshold = threshold,
                    unique_ip_ratio = ratio,
                    "DEFENSE MODE SOFT: Traffic anomaly in grey zone"
                );
            }
        } else {
            // Traffic is normal — check if we should deactivate defense mode
            if self.defense_active.load(Ordering::Relaxed) {
                // Cool-down: deactivate after 5 min below threshold
                let since = self.defense_since.read();
                if let Some(activated_at) = *since {
                    if activated_at.elapsed() > Duration::from_secs(300) {
                        self.deactivate_defense();
                        tracing::info!(
                            current_rps = current_rps,
                            baseline = baseline,
                            "Defense mode deactivated — traffic below threshold for 5 min"
                        );
                    }
                }
            }
        }
    }

    fn activate_defense(&self, level: DefenseLevel) {
        let was_active = self.defense_active.swap(true, Ordering::SeqCst);
        *self.defense_level.write() = level;
        if !was_active {
            *self.defense_since.write() = Some(Instant::now());
        }
    }

    fn deactivate_defense(&self) {
        self.defense_active.store(false, Ordering::SeqCst);
        *self.defense_level.write() = DefenseLevel::Off;
        *self.defense_since.write() = None;
    }

    /// Current RPS (last 3 seconds averaged)
    fn current_rps(&self) -> f64 {
        let buckets = self.second_buckets.read();
        let now = Instant::now();
        let window = Duration::from_secs(3);

        let recent: Vec<f64> = buckets
            .iter()
            .filter(|b| now.duration_since(b.timestamp) < window)
            .map(|b| b.count as f64)
            .collect();

        if recent.is_empty() {
            return 0.0;
        }

        recent.iter().sum::<f64>() / recent.len() as f64
    }

    /// Unique IP ratio in last 60s
    fn unique_ip_ratio(&self) -> f64 {
        let ips = self.recent_ips.read();
        if ips.is_empty() {
            return 1.0; // No data → assume legitimate
        }

        let total = ips.len() as f64;
        let unique: HashSet<IpAddr> = ips.iter().map(|(_, ip)| *ip).collect();
        let unique_count = unique.len() as f64;

        unique_count / total
    }

    /// Get defense mode status
    fn status(&self) -> DefenseModeStatus {
        let active = self.defense_active.load(Ordering::Relaxed);
        let level = *self.defense_level.read();
        let active_for_secs = if active {
            self.defense_since
                .read()
                .map(|s| s.elapsed().as_secs())
                .unwrap_or(0)
        } else {
            0
        };

        DefenseModeStatus {
            active,
            level,
            active_for_secs,
            current_rps: self.current_rps(),
            baseline_rps: *self.baseline_rps.read(),
            baseline_stddev: *self.baseline_stddev.read(),
            unique_ip_ratio: self.unique_ip_ratio(),
            tracked_ips: 0, // Filled by DDoSDetector
        }
    }
}

/// Anti-DoS del DDoS-detector stesso (sarebbe ironico se l'anti-DDoS fosse DoS-abile):
/// cap HARD del deque per-IP, indipendente dal RATE dell'attacco. 10_000 ≈ 1000 rps su
/// 10s → ben oltre qualunque soglia legittima; una sorgente oltre questo è già flood
/// conclamato e non serve accumulare altri Instant.
const MAX_TIMESTAMPS_PER_TRACKER: usize = 10_000;
/// Capacity HARD della LRU per-IP (`ShardedLru`): al superamento, l'inserimento di un IP
/// nuovo evicta la LRU in O(1) → bound della memoria in TEMPO REALE, strutturale. Sotto
/// IP-rotation i tracker sono tutti freschi: il vecchio soft-cap (enforce solo nella
/// cleanup periodica throttlata) lasciava crescere la mappa fra una cleanup e l'altra
/// = finestra-OOM. Ora il cap NON è più una leva temporale dell'attaccante.
const MAX_TRACKERS: usize = 100_000;
/// DD1 (CPU-DoS): la cleanup di RECLAIM (retain O(n) dei tracker stale) gira AL MASSIMO
/// ogni questo intervallo, throttlata nel TEMPO — MAI a ogni request. Non è più la leva
/// del bound (lo è `ShardedLru`): serve solo a liberare RAM degli IP idle prima che la
/// LRU li sfratti naturalmente.
const DDOS_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// DDoS Detector with Global Defense Mode
pub struct DDoSDetector {
    /// Per-IP request tracking. `ShardedLru` → bound HARD realtime (evict LRU O(1)).
    trackers: ShardedLru<IpAddr, RequestTracker>,
    /// Global traffic monitor (WI-11)
    monitor: GlobalTrafficMonitor,
    /// Thresholds
    volumetric_threshold_rps: f64,
    /// DD1: ultimo retain O(n) — per throttlare la cleanup nel TEMPO.
    last_cleanup: Mutex<Instant>,
    /// Quante volte il retain O(n) ha girato davvero (metrica + osservabilità test DD1).
    cleanup_runs: AtomicU64,
}

impl DDoSDetector {
    /// Create a new DDoS detector
    pub fn new() -> Self {
        Self {
            trackers: ShardedLru::new(MAX_TRACKERS),
            monitor: GlobalTrafficMonitor::new(),
            volumetric_threshold_rps: 50.0,
            last_cleanup: Mutex::new(Instant::now()),
            cleanup_runs: AtomicU64::new(0),
        }
    }

    /// Builder (test/tuning): override della capacity HARD della LRU per-IP (anti-OOM).
    pub fn with_max_trackers(mut self, max: usize) -> Self {
        self.trackers = ShardedLru::new(max.max(1));
        self
    }

    /// Check for DDoS patterns
    pub async fn check(&self, ip: IpAddr, request: &Request) -> Option<DDoSPattern> {
        // Record in global monitor
        self.monitor.record(ip);
        self.maybe_cleanup();

        let path = &request.path;

        // Effective thresholds — halved in full defense mode (calcolate fuori dal lock).
        let defense_full = self.is_defense_mode_full();
        let effective_threshold = if defense_full {
            self.volumetric_threshold_rps / 2.0
        } else {
            self.volumetric_threshold_rps
        };
        // Tighter thresholds in defense mode.
        let (min_requests, max_unique) = if defense_full {
            (15, 2) // Halved thresholds
        } else {
            (30, 3)
        };

        // Get-or-create tracker per-IP + valuta tutto sotto UN solo lock dello shard.
        // `ShardedLru`: se lo shard è pieno, l'inserimento dell'IP nuovo evicta la LRU in
        // O(1) (bound HARD realtime, niente soft-cap-window né sort O(n) sull'hot-path).
        self.trackers.with_entry_mut(ip, RequestTracker::new, |tracker| {
            tracker.record(path);

            // Check volumetric attack
            if tracker.requests_per_second() > effective_threshold {
                return Some(DDoSPattern::Volumetric);
            }

            // Check application layer attack (same endpoint repeatedly)
            let total_requests = tracker.requests_last_10s();
            let unique_endpoints = tracker.unique_endpoints();
            if total_requests > min_requests && unique_endpoints < max_unique {
                return Some(DDoSPattern::ApplicationLayer);
            }

            None
        })
    }

    /// Whether defense mode is active (any level)
    pub fn is_defense_mode_active(&self) -> bool {
        self.monitor.defense_active.load(Ordering::Relaxed)
    }

    /// Whether defense mode is FULL (aggressive)
    pub fn is_defense_mode_full(&self) -> bool {
        matches!(*self.monitor.defense_level.read(), DefenseLevel::Full)
    }

    /// Get defense mode level
    pub fn defense_level(&self) -> DefenseLevel {
        *self.monitor.defense_level.read()
    }

    /// Get defense mode status (for /defense-mode API)
    pub fn defense_status(&self) -> DefenseModeStatus {
        let mut status = self.monitor.status();
        status.tracked_ips = self.trackers.len();
        status
    }

    /// Check if we're under global attack (legacy API)
    pub fn is_under_global_attack(&self) -> bool {
        self.monitor.defense_active.load(Ordering::Relaxed)
    }

    /// Get current global RPS
    pub fn global_rps(&self) -> f64 {
        self.monitor.current_rps()
    }

    /// Get baseline RPS
    pub fn baseline_rps(&self) -> f64 {
        *self.monitor.baseline_rps.read()
    }

    /// Set volumetric threshold
    pub fn set_volumetric_threshold(&mut self, rps: f64) {
        self.volumetric_threshold_rps = rps;
    }

    /// Get tracked IP count
    pub fn tracked_ips(&self) -> usize {
        self.trackers.len()
    }

    /// Numero di retain O(n) effettivamente eseguiti (metrica + test DD1).
    pub fn cleanup_runs(&self) -> u64 {
        self.cleanup_runs.load(Ordering::Relaxed)
    }

    /// RECLAIM dei tracker stale (idle) per liberare RAM prima che la LRU li sfratti.
    /// NON è il bound della mappa: quello è strutturale in `ShardedLru` (evict O(1) al
    /// superamento di MAX_TRACKERS). Qui niente più soft-cap + sort O(n) (classe DD1
    /// rimossa) — solo un retain-by-stale throttlato nel TEMPO.
    fn maybe_cleanup(&self) {
        // Only cleanup occasionally
        if self.trackers.len() < 10000 {
            return;
        }
        // DD1 (CPU-DoS): throttle TEMPORALE. Il retain O(n) NON deve girare a ogni request
        // (sotto flood = O(n)×rate). Gira al massimo ogni DDOS_CLEANUP_INTERVAL.
        {
            let mut last = self.last_cleanup.lock();
            if last.elapsed() < DDOS_CLEANUP_INTERVAL {
                return;
            }
            *last = Instant::now();
        }
        self.cleanup_runs.fetch_add(1, Ordering::Relaxed);
        self.trackers.retain(|_, tracker| !tracker.is_stale());
    }
}

impl Default for DDoSDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_normal_traffic() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let request = Request {
            client_ip: ip,
            path: "/api/posts".to_string(),
            ..Default::default()
        };

        let pattern = detector.check(ip, &request).await;
        assert!(pattern.is_none());
    }

    #[tokio::test]
    async fn test_volumetric_detection() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Simulate high request rate
        for i in 0..100 {
            let request = Request {
                client_ip: ip,
                path: format!("/api/endpoint{}", i),
                ..Default::default()
            };
            detector.check(ip, &request).await;
        }

        // Should detect volumetric attack
        let request = Request {
            client_ip: ip,
            path: "/api/test".to_string(),
            ..Default::default()
        };
        let pattern = detector.check(ip, &request).await;
        assert!(pattern.is_some());
    }

    #[tokio::test]
    async fn test_application_layer_detection() {
        // Use a higher volumetric threshold so app-layer triggers first
        let mut detector = DDoSDetector::new();
        detector.set_volumetric_threshold(200.0);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Hit same endpoint many times (above app-layer threshold of 30,
        // but below the raised volumetric threshold)
        for _ in 0..35 {
            let request = Request {
                client_ip: ip,
                path: "/api/login".to_string(),
                ..Default::default()
            };
            detector.check(ip, &request).await;
        }

        // Should detect app layer attack (>30 requests to <3 unique endpoints)
        let request = Request {
            client_ip: ip,
            path: "/api/login".to_string(),
            ..Default::default()
        };
        let pattern = detector.check(ip, &request).await;
        assert_eq!(pattern, Some(DDoSPattern::ApplicationLayer));
    }

    #[test]
    fn test_defense_mode_starts_off() {
        let detector = DDoSDetector::new();
        assert!(!detector.is_defense_mode_active());
        assert_eq!(detector.defense_level(), DefenseLevel::Off);
    }

    /// 🚨 EL1-B (ddos): il deque timestamps per-IP NON deve crescere col RATE dell'attacco.
    /// Pre-fix: solo cutoff temporale (10s) → un flood costante accumula rate×finestra
    /// Instant prima che scadano. Ora cap HARD a MAX_TIMESTAMPS_PER_TRACKER.
    #[tokio::test]
    async fn timestamps_deque_bounded_under_flood() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let request = Request { client_ip: ip, path: "/x".to_string(), ..Default::default() };
        for _ in 0..20_000 {
            let _ = detector.check(ip, &request).await;
        }
        let len = detector
            .trackers
            .with_peek(&ip, |t| t.map(|t| t.timestamps.len()).unwrap_or(0));
        assert!(
            len <= MAX_TIMESTAMPS_PER_TRACKER,
            "EL1-B: deque timestamps non bounded sotto flood ({len} > {MAX_TIMESTAMPS_PER_TRACKER})"
        );
    }

    /// 🚨 DD1/OOM: la mappa `trackers` è bounded in TEMPO REALE sotto IP-rotation
    /// (`ShardedLru` evict-LRU O(1) all'inserimento), NON solo via la cleanup periodica
    /// throttlata. Pre-fix: il cap era enforced SOLO nella cleanup (throttlata a 10s) →
    /// fra una cleanup e l'altra un flood di IP distinti cresceva oltre il cap = finestra
    /// OOM. Con cap basso la cleanup non scatta mai (len<10k): isola il bound STRUTTURALE.
    #[tokio::test]
    async fn ddos_trackers_bounded_realtime_under_ip_rotation() {
        // cap multiplo dei 16 shard → capacity()==cap; 5000 IP distinti saturano ogni shard.
        let cap = 64;
        let detector = DDoSDetector::new().with_max_trackers(cap);
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(172, b[1], b[2], b[3]));
            let request = Request { client_ip: ip, path: "/x".to_string(), ..Default::default() };
            let _ = detector.check(ip, &request).await;
        }
        // == cap (non solo <=): uccide SIA "unbounded" (>cap) SIA la false-green
        // "non-inserisce-mai" (tracked_ips()==0 <= cap passerebbe).
        assert_eq!(
            detector.tracked_ips(),
            cap,
            "DD1/OOM: trackers deve essere bounded realtime ED esattamente pieno a cap={cap} (got {})",
            detector.tracked_ips()
        );
        // La cleanup throttlata NON è scattata (len<10k) → il bound è puramente strutturale.
        assert_eq!(detector.cleanup_runs(), 0, "il bound non deve dipendere dalla cleanup");
    }

    /// 🚨 DD1 (CPU-DoS): la cleanup O(n) deve essere throttlata nel TEMPO, non innescata
    /// dalla dimensione della mappa (leva dell'attaccante). Sopra 10k IP, oltre 600 request
    /// nello stesso istante NON devono far girare 600 retain O(n) — al massimo 1 per
    /// intervallo. Pre-fix (throttle solo per size): cleanup_runs ≈ 600.
    #[tokio::test]
    async fn dd1_cleanup_throttled_by_time_not_size() {
        let detector = DDoSDetector::new();
        // Supera la soglia 10k con IP distinti (simula IP-rotation).
        for i in 0..10_600u32 {
            let b = i.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(10, b[1], b[2], b[3]));
            let request = Request { client_ip: ip, path: "/x".to_string(), ..Default::default() };
            let _ = detector.check(ip, &request).await;
        }
        assert!(
            detector.cleanup_runs() <= 1,
            "DD1: il retain O(n) non è throttlato nel tempo (è girato {} volte sotto burst)",
            detector.cleanup_runs()
        );
    }

    #[test]
    fn test_defense_status_serializes() {
        let detector = DDoSDetector::new();
        let status = detector.defense_status();
        assert!(!status.active);
        assert_eq!(status.level, DefenseLevel::Off);
        assert_eq!(status.active_for_secs, 0);
        // Should be serializable
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"active\":false"));
    }

    #[test]
    fn test_unique_ip_ratio_calculation() {
        let monitor = GlobalTrafficMonitor::new();

        // Record same IP 10 times → ratio should be low
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..10 {
            monitor.record(ip);
        }
        let ratio = monitor.unique_ip_ratio();
        assert!(ratio < 0.2, "Same IP 10 times should have low ratio, got {}", ratio);

        // Record 10 different IPs → ratio should be higher
        let monitor2 = GlobalTrafficMonitor::new();
        for i in 0..10 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            monitor2.record(ip);
        }
        let ratio2 = monitor2.unique_ip_ratio();
        assert!(ratio2 > 0.9, "10 different IPs should have high ratio, got {}", ratio2);
    }
}
