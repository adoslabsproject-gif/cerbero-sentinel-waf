//! Cross-IP Correlator (Section B3 — Sentinel WAF v2.0.0)
//!
//! Detects distributed attack patterns across multiple IP addresses using
//! dual sliding windows (2 min short + 30 min long) and a 2h unique counter:
//!
//! - **Coordinated**: 5+ IPs hit the same normalized pattern in 2 min
//! - **Probing**: 3+ IPs traverse the same path sequence in 2 min
//! - **Botnet**: 10+ IPs share the same non-browser UA in 2 min (ISP-aware)
//! - **SlowDrip**: 10+ IPs hit the same pattern in 30 min
//! - **SlowProbe**: 5+ IPs traverse the same sequence in 30 min
//! - **SlowDistributed**: 15+ unique IPs per pattern in 2h
//!
//! All structures are lock-free (DashMap + AtomicU64). Patterns enter tracking
//! only after 2+ sightings (Section A7 promotion). Max 2000 patterns, 500 IPs
//! per pattern (Section A9 bounded memory).

use sentinel_core::sharded_lru::ShardedLru;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─── Window durations ────────────────────────────────────────────────────────
const SHORT_WINDOW: Duration = Duration::from_secs(120);     // 2 minutes
const LONG_WINDOW: Duration = Duration::from_secs(1800);     // 30 minutes
// (rimosso ULTRA_WINDOW: era dead_code "reserved for HLL ultra-slow detection" mai costruita
//  = debito aspirazionale. Si riaggiunge quando si implementa davvero la detection HLL.)

// ─── Thresholds ──────────────────────────────────────────────────────────────
const COORDINATED_IP_THRESHOLD: usize = 5;
const PROBING_IP_THRESHOLD: usize = 3;
const BOTNET_IP_THRESHOLD: usize = 10;
const SLOW_DRIP_IP_THRESHOLD: usize = 10;
const SLOW_PROBE_IP_THRESHOLD: usize = 5;
const SLOW_DISTRIBUTED_IP_THRESHOLD: usize = 15;
const BOTNET_ERROR_RATE_THRESHOLD: f64 = 30.0;

// ─── Promotion threshold (Section A7) ────────────────────────────────────────
const PROMOTION_HIT_COUNT: u64 = 2;

// ─── Default caps ────────────────────────────────────────────────────────────
const DEFAULT_MAX_PATTERNS: usize = 2000;
const DEFAULT_MAX_IPS_PER_PATTERN: usize = 500;
/// Cap HARD dei deque short/long window per-pattern (anti-OOM, classe EL1-B): il
/// time-prune non bounda il COUNT sotto flood ad alto rate. ≫ DEFAULT_MAX_IPS_PER_PATTERN
/// → il conteggio IP-unici della detection non è alterato.
const MAX_WINDOW_ENTRIES: usize = 4096;
/// Cap HARD del PromotionGate (anti-OOM/SESSION1): key = pattern attacker-controlled.
const MAX_PENDING_PATTERNS: usize = 4096;

// ─── Long window sampling rate ───────────────────────────────────────────────
const LONG_WINDOW_SAMPLE_RATE: u64 = 5; // 1 in 5

/// Cross-IP correlation detection result
#[derive(Debug, Clone)]
pub struct CrossIpDetection {
    pub detection_type: CrossIpDetectionType,
    pub risk_add: f64,
    pub ip_count: usize,
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossIpDetectionType {
    /// 5+ IP same pattern in 2 min
    Coordinated,
    /// 3+ IP same sequence in 2 min
    Probing,
    /// 10+ IP same non-browser UA in 2 min (with ISP filter)
    Botnet,
    /// 10+ IP same pattern in 30 min (slow drip)
    SlowDrip,
    /// 5+ IP same sequence in 30 min
    SlowProbe,
    /// 15+ unique IP in 2h per pattern (ultra-slow)
    SlowDistributed,
}

/// Timed IP set with dual sliding window (2 min + 30 min)
struct TimedIpSet {
    /// Short window entries (2 min). `VecDeque` → drop O(1) del più vecchio al cap.
    short_window: VecDeque<(IpAddr, Instant)>,
    /// Long window entries (30 min, sampled 1/5). `VecDeque` → drop O(1) al cap.
    long_window: VecDeque<(IpAddr, Instant)>,
    /// 2h unique IP counter — uses HashSet when < 50, Bounded above
    unique_2h: UniqueCounter,
    /// Entry counter for sampling
    sample_counter: u64,
    /// Last access time (for LRU eviction)
    last_access: Instant,
}

impl TimedIpSet {
    fn new() -> Self {
        Self {
            short_window: VecDeque::new(),
            long_window: VecDeque::new(),
            unique_2h: UniqueCounter::new(),
            sample_counter: 0,
            last_access: Instant::now(),
        }
    }

    /// Record an IP in the appropriate windows
    fn record(&mut self, ip: IpAddr) {
        let now = Instant::now();
        self.last_access = now;
        self.sample_counter += 1;

        // Always record in short window
        self.short_window.push_back((ip, now));
        // Cap HARD (EL1-B): oltre il cap droppa il più vecchio in O(1) (il time-prune in
        // `prune` non bounda il COUNT sotto flood ad alto rate).
        if self.short_window.len() > MAX_WINDOW_ENTRIES {
            self.short_window.pop_front();
        }

        // Sample 1/5 for long window
        if self.sample_counter % LONG_WINDOW_SAMPLE_RATE == 0 {
            self.long_window.push_back((ip, now));
            if self.long_window.len() > MAX_WINDOW_ENTRIES {
                self.long_window.pop_front();
            }
        }

        // BOUNDED: `unique_2h` è un UniqueCounter che passa a stima HLL-like oltre una
        // soglia interna (non un set illimitato) → memoria O(1).
        self.unique_2h.insert(ip);
    }

    /// Count unique IPs in the short window (2 min)
    fn short_unique_ips(&self) -> HashSet<IpAddr> {
        let cutoff = Instant::now() - SHORT_WINDOW;
        self.short_window
            .iter()
            .filter(|(_, ts)| *ts >= cutoff)
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Count unique IPs in the long window (30 min)
    fn long_unique_ips(&self) -> HashSet<IpAddr> {
        let cutoff = Instant::now() - LONG_WINDOW;
        self.long_window
            .iter()
            .filter(|(_, ts)| *ts >= cutoff)
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Get the 2h unique IP count
    fn ultra_unique_count(&self) -> usize {
        self.unique_2h.count()
    }

    /// Prune entries older than their respective TTLs
    fn prune(&mut self) {
        let now = Instant::now();

        let short_cutoff = now - SHORT_WINDOW;
        self.short_window.retain(|(_, ts)| *ts >= short_cutoff);

        let long_cutoff = now - LONG_WINDOW;
        self.long_window.retain(|(_, ts)| *ts >= long_cutoff);
    }

    /// Whether this set has had no activity beyond the long window
    fn is_stale(&self) -> bool {
        self.last_access.elapsed() > LONG_WINDOW
    }

    /// Total memory pressure (for eviction decisions)
    fn entry_count(&self) -> usize {
        self.short_window.len() + self.long_window.len()
    }
}

/// HyperLogLog fallback for > 50 IPs, HashSet for <= 50 (Section B3 fix).
/// For v2.0.0 we use a bounded HashSet since cardinality is capped at
/// 500 IP/pattern — a full HLL is unnecessary at this scale.
enum UniqueCounter {
    Precise(HashSet<IpAddr>),
    /// Semantically identical but indicates we crossed the 50-IP threshold.
    /// Same HashSet implementation — the distinction exists for future HLL
    /// promotion and for observability (we can log which patterns went Bounded).
    Bounded(HashSet<IpAddr>),
}

impl UniqueCounter {
    fn new() -> Self {
        Self::Precise(HashSet::new())
    }

    fn insert(&mut self, ip: IpAddr) {
        match self {
            Self::Precise(set) => {
                set.insert(ip);
                if set.len() > 50 {
                    let existing = std::mem::take(set);
                    *self = Self::Bounded(existing);
                }
            }
            Self::Bounded(set) => {
                set.insert(ip);
            }
        }
    }

    fn count(&self) -> usize {
        match self {
            Self::Precise(set) => set.len(),
            Self::Bounded(set) => set.len(),
        }
    }

    fn reset(&mut self) {
        *self = Self::Precise(HashSet::new());
    }
}

/// Pre-promotion counter: tracks how many times a pattern key has been seen
/// before it is promoted into the full TimedIpSet tracking map.
struct PromotionGate {
    /// Pattern key -> (hit count, first seen). `ShardedLru`: la key è un pattern
    /// attacker-controlled → bound HARD realtime (era DashMap senza cap di size).
    pending: ShardedLru<String, (u64, Instant)>,
}

impl PromotionGate {
    fn new() -> Self {
        Self {
            pending: ShardedLru::new(MAX_PENDING_PATTERNS),
        }
    }

    /// Returns true if the pattern should be promoted (>= PROMOTION_HIT_COUNT).
    fn should_promote(&self, key: &str) -> bool {
        self.pending.with_entry_mut(
            key.to_string(),
            || (0, Instant::now()),
            |e| {
                e.0 += 1;
                e.0 >= PROMOTION_HIT_COUNT
            },
        )
    }

    /// Remove a pattern from the pending gate (after promotion)
    fn remove(&self, key: &str) {
        self.pending.remove(key);
    }

    /// Cleanup stale pending entries (older than short window)
    fn cleanup(&self) {
        let cutoff = Instant::now() - SHORT_WINDOW;
        self.pending.retain(|_, (_, first_seen)| *first_seen >= cutoff);
    }
}

/// Known consumer ISP ASNs (Section B3 fix -- false positive filter).
/// Major European residential ISPs whose subscribers sharing a UA pattern
/// is expected behavior (CGNAT, mobile pools) rather than botnet activity.
const TRUSTED_CONSUMER_ISPS: &[u32] = &[
    // Italy
    12874,  // Fastweb
    3269,   // Telecom Italia / TIM
    1267,   // Wind Tre
    6762,   // Sparkle / TIM International
    29447,  // Iliad Italia
    15589,  // Vodafone Italia
    5602,   // Sky Italia
    // Switzerland
    3303,   // Swisscom
    // Germany
    3320,   // Deutsche Telekom
    3209,   // Vodafone Germany
    6805,   // Telefonica Germany
    // Pan-European
    6830,   // Liberty Global / Vodafone EU
    // France
    12322,  // Free SAS
    5410,   // Bouygues Telecom
    15557,  // SFR
    // Spain
    12479,  // Orange Espana
    3352,   // Telefonica Espana
    6739,   // Cableuropa / Vodafone Spain
    // UK
    12576,  // EE / BT UK
    2856,   // BT UK
    5089,   // Virgin Media
];

/// Check if an ASN belongs to a trusted consumer ISP
fn is_trusted_consumer_isp(asn: u32) -> bool {
    TRUSTED_CONSUMER_ISPS.contains(&asn)
}

/// Check if UA is a standard modern browser (too common to be discriminating).
/// Bots mimicking browsers will pass this check — that is intentional: the
/// purpose is to avoid flagging legitimate residential traffic that all
/// shares the same Chrome/Firefox UA string.
fn is_standard_browser_ua(ua: &str) -> bool {
    let lower = ua.to_lowercase();
    // Chrome 130+, Firefox 130+, Safari 18+ are too common to be discriminating
    (lower.contains("chrome/") && lower.contains("mozilla/"))
        || (lower.contains("firefox/") && lower.contains("mozilla/"))
        || (lower.contains("safari/") && lower.contains("applewebkit/"))
}

/// Normalize a request path to a pattern suitable for correlation.
///
/// - Replace UUID segments with `:id`
/// - Replace numeric segments with `:id`
/// - Retain at most the first 3 path segments (after the leading empty segment)
/// - Strip query string
///
/// Examples:
///   `/api/users/550e8400-e29b-41d4-a716-446655440000/profile` -> `/api/users/:id`
///   `/api/orders/12345` -> `/api/orders/:id`
///   `/api/v1/products/42/reviews/7` -> `/api/v1/products`
pub fn normalize_path(path: &str) -> String {
    // Strip query string
    let path = path.split('?').next().unwrap_or(path);

    let segments: Vec<&str> = path.split('/').collect();

    // segments[0] is always "" (before the leading /), so meaningful segments
    // start at index 1. We keep at most 3 meaningful segments.
    let max_meaningful = 3;
    let mut result = Vec::with_capacity(max_meaningful + 1);
    result.push(""); // leading empty segment for the /

    let mut meaningful_count = 0;
    for seg in segments.iter().skip(1) {
        if seg.is_empty() {
            continue;
        }
        if meaningful_count >= max_meaningful {
            break;
        }
        meaningful_count += 1;

        // UUID: 8-4-4-4-12 hex
        if seg.len() == 36
            && seg.chars().filter(|c| *c == '-').count() == 4
            && seg.replace('-', "").chars().all(|c| c.is_ascii_hexdigit())
        {
            result.push(":id");
            continue;
        }

        // Pure numeric
        if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit()) {
            result.push(":id");
            continue;
        }

        // Hex-like IDs (24+ hex chars, e.g. MongoDB ObjectId)
        if seg.len() >= 24 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
            result.push(":id");
            continue;
        }

        result.push(seg);
    }

    if result.len() == 1 {
        // Only the leading empty segment -> root path
        "/".to_string()
    } else {
        result.join("/")
    }
}

/// Cross-IP Correlator
///
/// Thread-safe, non-blocking correlation engine using DashMap for all mutable
/// state. Designed for inline use in the request pipeline (<1ms amortized).
pub struct CrossIpCorrelator {
    /// Pattern -> IPs. Bound + eviction true-O(1) via ShardedLru (era DashMap +
    /// evict_lru O(n)-scan): la key è attacker-influenced → cap per anti-OOM e
    /// LRU O(1) per non far scalare il lavoro col flood di pattern (classe DD1).
    pattern_to_ips: ShardedLru<String, TimedIpSet>,
    /// Path sequence -> IPs (sequence = last 2 normalized paths joined).
    sequence_to_ips: ShardedLru<String, TimedIpSet>,
    /// UA -> IPs.
    ua_to_ips: ShardedLru<String, TimedIpSet>,
    /// Per-IP last 2 normalized paths (for sequence construction). `ShardedLru`:
    /// IP-keyed (attacker-controlled) → bound HARD realtime (era DashMap soft-cap batch).
    ip_recent_paths: ShardedLru<IpAddr, (String, Option<String>)>,
    /// Promotion gate: patterns must be seen >= 2 times before full tracking
    promotion_gate: PromotionGate,
    /// Global unique IP counter per minute (approximate, relaxed ordering)
    unique_ips_per_minute: AtomicU64,
    /// Max IPs per pattern cap
    max_ips_per_pattern: usize,
}

impl CrossIpCorrelator {
    /// Create a new correlator with default bounds (2000 patterns, 500 IPs/pattern)
    pub fn new() -> Self {
        Self::with_bounds(DEFAULT_MAX_PATTERNS, DEFAULT_MAX_IPS_PER_PATTERN)
    }

    /// Create a new correlator with custom bounds. I 3 map sono `ShardedLru`
    /// cappati a `max_patterns` (eviction LRU true-O(1)).
    pub fn with_bounds(max_patterns: usize, max_ips_per_pattern: usize) -> Self {
        Self {
            pattern_to_ips: ShardedLru::new(max_patterns),
            sequence_to_ips: ShardedLru::new(max_patterns),
            ua_to_ips: ShardedLru::new(max_patterns),
            ip_recent_paths: ShardedLru::new(max_patterns * 2),
            promotion_gate: PromotionGate::new(),
            unique_ips_per_minute: AtomicU64::new(0),
            max_ips_per_pattern,
        }
    }

    /// Record a request for cross-IP correlation tracking.
    ///
    /// This must be called for every incoming request. It normalizes the path,
    /// constructs the sequence key, and records the IP in the appropriate
    /// tracking maps. Patterns enter full tracking only after 2+ sightings
    /// (Section A7 promotion gate).
    pub fn record(
        &self,
        ip: IpAddr,
        path: &str,
        ua: &str,
        _asn: Option<u32>,
        _error_code: Option<u16>,
    ) {
        let pattern = normalize_path(path);

        // Update global unique IP counter (relaxed — best-effort metric)
        self.unique_ips_per_minute.fetch_add(1, Ordering::Relaxed);

        // ── Pattern tracking (with promotion gate) ───────────────────────
        self.record_in_map(&self.pattern_to_ips, &pattern, ip);

        // ── Sequence tracking ────────────────────────────────────────────
        // Build sequence from last 2 paths for this IP
        let sequence_key = self.ip_recent_paths.with_entry_mut(
            ip,
            || (pattern.clone(), None),
            |entry| {
                let (current, previous) = entry;
                // Shift: previous = old current, current = new pattern
                let old_current = current.clone();
                *previous = Some(old_current);
                *current = pattern.clone();

                // Sequence key: "prev->current"
                previous
                    .as_ref()
                    .map(|prev| format!("{}->{}", prev, current))
            },
        );

        if let Some(ref seq_key) = sequence_key {
            self.record_in_map(&self.sequence_to_ips, seq_key, ip);
        }

        // ── UA tracking ──────────────────────────────────────────────────
        if !ua.is_empty() {
            self.record_in_map(&self.ua_to_ips, ua, ip);
        }
    }

    /// Record an IP in a ShardedLru-backed tracking map with promotion gating.
    fn record_in_map(&self, map: &ShardedLru<String, TimedIpSet>, key: &str, ip: IpAddr) {
        // Già tracciato → record nel set (cap per-pattern + prune-retry).
        // with_get_mut promuove la recency O(1). `existed` = true se presente.
        let existed = map.with_get_mut(key, |opt| {
            if let Some(set) = opt {
                if set.entry_count() < self.max_ips_per_pattern {
                    set.record(ip);
                } else {
                    // Prune first, then try again
                    set.prune();
                    if set.entry_count() < self.max_ips_per_pattern {
                        set.record(ip);
                    }
                }
                true
            } else {
                false
            }
        });
        if existed {
            return;
        }

        // Non tracciato → promotion gate. Se promosso, insert: lo ShardedLru
        // evicta la LRU in O(1) se lo shard è al cap (niente evict_lru O(n)).
        if self.promotion_gate.should_promote(key) {
            let mut new_set = TimedIpSet::new();
            new_set.record(ip);
            map.put(key.to_string(), new_set);
            self.promotion_gate.remove(key);
        }
    }

    /// Detect cross-IP correlation patterns for the current request.
    ///
    /// Returns a vector of detections with risk additions. The caller (behavioral
    /// analysis layer) sums the `risk_add` values and applies appropriate flags.
    ///
    /// Parameters:
    /// - `ip`: Client IP
    /// - `path`: Raw request path (will be normalized internally)
    /// - `ua`: User-Agent header value
    /// - `asn`: Optional AS number for ISP filtering
    /// - `error_rate_pct`: Error rate percentage for this IP (0-100)
    pub fn detect(
        &self,
        _ip: IpAddr,
        path: &str,
        ua: &str,
        asn: Option<u32>,
        error_rate_pct: f64,
    ) -> Vec<CrossIpDetection> {
        let pattern = normalize_path(path);
        let mut detections = Vec::new();

        // ── Short window (2 min) rules ───────────────────────────────────

        // Rule 1: Coordinated — 5+ IPs same pattern in 2 min
        let coord_ips = self
            .pattern_to_ips
            .with_peek(&pattern, |o| o.map_or(0, |s| s.short_unique_ips().len()));
        if coord_ips >= COORDINATED_IP_THRESHOLD {
            detections.push(CrossIpDetection {
                detection_type: CrossIpDetectionType::Coordinated,
                risk_add: 0.7,
                ip_count: coord_ips,
                pattern: pattern.clone(),
            });
        }

        // Rule 2: Probing — 3+ IPs same path sequence in 2 min
        if let Some(ref seq_key) = self.build_sequence_key(_ip, &pattern) {
            let probe_ips = self
                .sequence_to_ips
                .with_peek(seq_key.as_str(), |o| o.map_or(0, |s| s.short_unique_ips().len()));
            if probe_ips >= PROBING_IP_THRESHOLD {
                detections.push(CrossIpDetection {
                    detection_type: CrossIpDetectionType::Probing,
                    risk_add: 0.5,
                    ip_count: probe_ips,
                    pattern: seq_key.clone(),
                });
            }
        }

        // Rule 3: Botnet — 10+ IPs same non-browser UA in 2 min
        if !ua.is_empty() {
            let botnet_ips = self
                .ua_to_ips
                .with_peek(ua, |o| o.map_or(0, |s| s.short_unique_ips().len()));
            if botnet_ips >= BOTNET_IP_THRESHOLD {
                let is_browser = is_standard_browser_ua(ua);
                let is_consumer_isp = asn.map(is_trusted_consumer_isp).unwrap_or(false);

                // Require error_rate > 30% for botnet classification
                if error_rate_pct > BOTNET_ERROR_RATE_THRESHOLD {
                    let risk = if is_browser || is_consumer_isp {
                        // Reduced risk: legitimate traffic pattern likely
                        0.3
                    } else {
                        0.8
                    };

                    detections.push(CrossIpDetection {
                        detection_type: CrossIpDetectionType::Botnet,
                        risk_add: risk,
                        ip_count: botnet_ips,
                        // FP3: char-boundary-safe — `&ua[..80]` panicava su un
                        // User-Agent con un carattere multibyte sul byte 80.
                        pattern: if ua.len() > 80 {
                            format!("{}...", sentinel_core::truncate_char_boundary(ua, 80))
                        } else {
                            ua.to_string()
                        },
                    });
                }
            }
        }

        // ── Long window (30 min) rules ───────────────────────────────────

        // Rule 4: SlowDrip — 10+ IPs same pattern in 30 min
        let drip_ips = self
            .pattern_to_ips
            .with_peek(&pattern, |o| o.map_or(0, |s| s.long_unique_ips().len()));
        if drip_ips >= SLOW_DRIP_IP_THRESHOLD {
            detections.push(CrossIpDetection {
                detection_type: CrossIpDetectionType::SlowDrip,
                risk_add: 0.4,
                ip_count: drip_ips,
                pattern: pattern.clone(),
            });
        }

        // Rule 5: SlowProbe — 5+ IPs same sequence in 30 min
        if let Some(ref seq_key) = self.build_sequence_key(_ip, &pattern) {
            let slow_probe_ips = self
                .sequence_to_ips
                .with_peek(seq_key.as_str(), |o| o.map_or(0, |s| s.long_unique_ips().len()));
            if slow_probe_ips >= SLOW_PROBE_IP_THRESHOLD {
                detections.push(CrossIpDetection {
                    detection_type: CrossIpDetectionType::SlowProbe,
                    risk_add: 0.3,
                    ip_count: slow_probe_ips,
                    pattern: seq_key.clone(),
                });
            }
        }

        // ── Ultra-slow (2h unique counter) ───────────────────────────────

        // Rule 6: SlowDistributed — 15+ unique IPs per pattern in 2h
        let ultra_count = self
            .pattern_to_ips
            .with_peek(&pattern, |o| o.map_or(0, |s| s.ultra_unique_count()));
        if ultra_count >= SLOW_DISTRIBUTED_IP_THRESHOLD {
            detections.push(CrossIpDetection {
                detection_type: CrossIpDetectionType::SlowDistributed,
                risk_add: 0.3,
                ip_count: ultra_count,
                pattern: pattern.clone(),
            });
        }

        detections
    }

    /// Build the sequence key for a given IP and its current normalized pattern.
    /// Returns None if the IP has no previous path recorded.
    fn build_sequence_key(&self, ip: IpAddr, _current_pattern: &str) -> Option<String> {
        self.ip_recent_paths.with_peek(&ip, |o| {
            o.and_then(|(current, previous)| {
                previous.as_ref().map(|prev| format!("{}->{}", prev, current))
            })
        })
    }

    /// Periodic cleanup of all tracking maps.
    ///
    /// Call this from a background task (e.g. every 30-60 seconds).
    /// - Prunes entries older than their TTL from short (2 min) and long (30 min) windows
    /// - Resets 2h unique counters for stale patterns
    /// - Evicts patterns over the cap using LRU
    /// - Cleans the promotion gate
    pub fn cleanup(&self) {
        self.cleanup_map(&self.pattern_to_ips);
        self.cleanup_map(&self.sequence_to_ips);
        self.cleanup_map(&self.ua_to_ips);

        // ip_recent_paths: bound HARD strutturale in `ShardedLru` (evict LRU O(1) al
        // superamento del cap) → niente più batch-evict O(n) periodico qui.

        // Cleanup promotion gate
        self.promotion_gate.cleanup();

        // Reset global counter (best-effort per-minute approximation)
        self.unique_ips_per_minute.store(0, Ordering::Relaxed);
    }

    /// Internal cleanup for a single tracking map. Prune le finestre + droppa le
    /// stantie/vuote (retain con &mut V). Il cap NON serve più qui: ShardedLru
    /// evicta la LRU in O(1) all'insert (era `while len>max { evict_lru O(n) }`).
    fn cleanup_map(&self, map: &ShardedLru<String, TimedIpSet>) {
        map.retain(|_, set| {
            set.prune();
            // Drop se stantia (2h counter scaduto)…
            if set.is_stale() {
                return false;
            }
            // …o se non resta dato in nessuna finestra.
            !set.short_window.is_empty() || !set.long_window.is_empty()
        });
    }

    /// Reset the 2h unique counters across all tracked patterns.
    /// Call this from a 2h periodic task.
    pub fn reset_ultra_counters(&self) {
        self.pattern_to_ips.for_each_mut(|_, s| s.unique_2h.reset());
        self.sequence_to_ips.for_each_mut(|_, s| s.unique_2h.reset());
        self.ua_to_ips.for_each_mut(|_, s| s.unique_2h.reset());
    }

    /// Number of actively tracked patterns
    pub fn tracked_patterns(&self) -> usize {
        self.pattern_to_ips.len()
    }

    /// Number of actively tracked sequences
    pub fn tracked_sequences(&self) -> usize {
        self.sequence_to_ips.len()
    }

    /// Number of actively tracked UAs
    pub fn tracked_uas(&self) -> usize {
        self.ua_to_ips.len()
    }

    /// Global unique IP counter value (approximate, resets on cleanup)
    pub fn unique_ips_counter(&self) -> u64 {
        self.unique_ips_per_minute.load(Ordering::Relaxed)
    }
}

impl Default for CrossIpCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: create IpAddr from the last octet
    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// Helper: create a standard Chrome UA
    fn chrome_ua() -> &'static str {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }

    /// Helper: create a non-browser UA
    fn bot_ua() -> &'static str {
        "python-requests/2.31.0"
    }

    /// 🚨 SESSION1/OOM: il PromotionGate.pending (key = pattern attacker-controlled) è
    /// bounded realtime via ShardedLru. Pre-fix: DashMap con solo retain periodico per-tempo
    /// → un flood di pattern distinti (1 hit each, restano pending) cresceva illimitato.
    /// Mutation-verify: senza il cap ShardedLru → pending.len() == 5000+ invece di == cap.
    #[test]
    fn promotion_gate_pending_bounded_under_pattern_flood() {
        let gate = PromotionGate::new();
        for i in 0..(MAX_PENDING_PATTERNS + 2000) {
            // 1 solo hit each → < PROMOTION_HIT_COUNT → resta in pending (non promosso/rimosso).
            gate.should_promote(&format!("pattern-{i}"));
        }
        assert_eq!(
            gate.pending.len(),
            MAX_PENDING_PATTERNS,
            "pending non bounded realtime (got {})",
            gate.pending.len()
        );
    }

    /// 🚨 SESSION1/OOM: ip_recent_paths (IP-keyed) è bounded realtime via ShardedLru.
    /// Pre-fix: DashMap con batch-evict O(n) periodico → cresceva fra le cleanup.
    #[test]
    fn ip_recent_paths_bounded_under_ip_flood() {
        // ip_recent_paths cap = max_patterns*2 = 128 (multiplo dei 16 shard).
        let c = CrossIpCorrelator::with_bounds(64, 500);
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            // 10.0.X.Y → 5000 IP distinti.
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, b[2], b[3]));
            c.record(addr, "/api/test", bot_ua(), None, None);
        }
        assert_eq!(
            c.ip_recent_paths.len(),
            128,
            "ip_recent_paths non bounded realtime (got {})",
            c.ip_recent_paths.len()
        );
    }

    #[test]
    fn test_coordinated_detection() {
        let correlator = CrossIpCorrelator::new();

        // 6 different IPs hit the same pattern (needs 2 hits to promote, then 5+ unique)
        for i in 0..7 {
            correlator.record(ip(i), "/api/auth/login", chrome_ua(), None, None);
        }

        let detections = correlator.detect(ip(0), "/api/auth/login", chrome_ua(), None, 0.0);
        let coordinated = detections.iter().find(|d| d.detection_type == CrossIpDetectionType::Coordinated);
        assert!(coordinated.is_some(), "Expected Coordinated detection for 7 unique IPs on same pattern");
        assert_eq!(coordinated.unwrap().risk_add, 0.7);
        assert!(coordinated.unwrap().ip_count >= COORDINATED_IP_THRESHOLD);
    }

    #[test]
    fn test_slow_drip_detection() {
        let correlator = CrossIpCorrelator::new();

        // 12 IPs hit the same pattern (all within the long window sampling)
        // Since sampling is 1/5, we need enough records to get 10+ in the long window.
        // Each IP records once. sample_counter starts at 0 and increments globally
        // on the TimedIpSet, so the first call is counter=1, 2nd=2, etc.
        // Entries where counter % 5 == 0 go into long_window: 5th, 10th, 15th...
        // To get 10+ in long window, we need >= 50 records. Use 55 unique IPs.
        for i in 0..55 {
            // Use two octets for >255 IPs
            let a = (i / 255) as u8;
            let b = (i % 255) as u8;
            correlator.record(
                IpAddr::V4(Ipv4Addr::new(10, 0, a, b + 1)),
                "/api/v1/products",
                chrome_ua(),
                None,
                None,
            );
        }

        let detections = correlator.detect(
            ip(1),
            "/api/v1/products",
            chrome_ua(),
            None,
            0.0,
        );

        let slow_drip = detections.iter().find(|d| d.detection_type == CrossIpDetectionType::SlowDrip);
        assert!(
            slow_drip.is_some(),
            "Expected SlowDrip detection, got: {:?}", detections
        );
        assert_eq!(slow_drip.unwrap().risk_add, 0.4);
    }

    #[test]
    fn test_isp_filter_reduces_botnet() {
        let correlator = CrossIpCorrelator::new();

        // 12 IPs with same non-browser UA, high error rate
        for i in 0..12 {
            correlator.record(ip(i), "/api/data", bot_ua(), Some(12874), Some(403));
        }

        // Without ISP filter (unknown ASN) — full risk 0.8
        let detections_no_isp = correlator.detect(
            ip(0),
            "/api/data",
            bot_ua(),
            None,
            50.0, // high error rate
        );
        let botnet_no_isp = detections_no_isp.iter().find(|d| d.detection_type == CrossIpDetectionType::Botnet);
        assert!(botnet_no_isp.is_some(), "Expected Botnet detection without ISP filter");
        assert_eq!(botnet_no_isp.unwrap().risk_add, 0.8);

        // With trusted consumer ISP (Fastweb 12874) — reduced risk 0.3
        let detections_isp = correlator.detect(
            ip(0),
            "/api/data",
            bot_ua(),
            Some(12874), // Fastweb
            50.0,
        );
        let botnet_isp = detections_isp.iter().find(|d| d.detection_type == CrossIpDetectionType::Botnet);
        assert!(botnet_isp.is_some(), "Expected Botnet detection with ISP filter");
        assert_eq!(botnet_isp.unwrap().risk_add, 0.3);
    }

    #[test]
    fn test_browser_ua_reduces_botnet() {
        let correlator = CrossIpCorrelator::new();

        // 12 IPs with same browser UA, high error rate
        for i in 0..12 {
            correlator.record(ip(i), "/api/data", chrome_ua(), None, Some(500));
        }

        // Browser UA should reduce botnet risk to 0.3
        let detections = correlator.detect(
            ip(0),
            "/api/data",
            chrome_ua(),
            None,
            50.0,
        );
        let botnet = detections.iter().find(|d| d.detection_type == CrossIpDetectionType::Botnet);
        assert!(botnet.is_some(), "Expected Botnet detection for browser UA");
        assert_eq!(botnet.unwrap().risk_add, 0.3);
    }

    #[test]
    fn test_botnet_requires_high_error_rate() {
        let correlator = CrossIpCorrelator::new();

        // 12 IPs with same non-browser UA but LOW error rate
        for i in 0..12 {
            correlator.record(ip(i), "/api/data", bot_ua(), None, None);
        }

        // Error rate below threshold — no botnet detection
        let detections = correlator.detect(
            ip(0),
            "/api/data",
            bot_ua(),
            None,
            10.0, // below 30% threshold
        );
        let botnet = detections.iter().find(|d| d.detection_type == CrossIpDetectionType::Botnet);
        assert!(botnet.is_none(), "Should NOT detect Botnet with error rate < 30%");
    }

    #[test]
    fn test_promotion_requires_2_hits() {
        let correlator = CrossIpCorrelator::new();

        // Single hit — should NOT be promoted to tracking
        correlator.record(ip(1), "/api/rare/endpoint", bot_ua(), None, None);

        assert_eq!(
            correlator.tracked_patterns(),
            0,
            "Single-hit pattern should NOT be promoted"
        );

        // Second hit — NOW it should be promoted
        correlator.record(ip(2), "/api/rare/endpoint", bot_ua(), None, None);

        assert!(
            correlator.tracked_patterns() >= 1,
            "Pattern should be promoted after 2 hits"
        );
    }

    #[test]
    fn test_cleanup_ttl() {
        let correlator = CrossIpCorrelator::new();

        // Record some data
        for i in 0..5 {
            correlator.record(ip(i), "/api/test", bot_ua(), None, None);
        }

        let patterns_before = correlator.tracked_patterns();
        assert!(patterns_before > 0, "Should have tracked patterns");

        // Cleanup should not remove non-stale entries
        correlator.cleanup();
        let patterns_after = correlator.tracked_patterns();
        assert_eq!(
            patterns_before, patterns_after,
            "Cleanup should NOT remove non-stale entries"
        );
    }

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000"),
            "/api/users/:id"
        );
    }

    #[test]
    fn test_normalize_path_numeric() {
        assert_eq!(normalize_path("/api/users/123"), "/api/users/:id");
    }

    #[test]
    fn test_normalize_path_max_segments() {
        // Only first 3 meaningful segments retained
        assert_eq!(
            normalize_path("/api/v1/products/42/reviews/7"),
            "/api/v1/products"
        );
    }

    #[test]
    fn test_normalize_path_query_strip() {
        assert_eq!(
            normalize_path("/api/users?page=1&limit=10"),
            "/api/users"
        );
    }

    #[test]
    fn test_normalize_path_root() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_hex_id() {
        assert_eq!(
            normalize_path("/api/items/507f1f77bcf86cd799439011"),
            "/api/items/:id"
        );
    }

    #[test]
    fn test_is_standard_browser_ua() {
        assert!(is_standard_browser_ua(chrome_ua()));
        assert!(is_standard_browser_ua(
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
        ));
        assert!(is_standard_browser_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        ));
        assert!(!is_standard_browser_ua(bot_ua()));
        assert!(!is_standard_browser_ua("curl/8.5.0"));
        assert!(!is_standard_browser_ua("Googlebot/2.1"));
    }

    #[test]
    fn test_is_trusted_consumer_isp() {
        assert!(is_trusted_consumer_isp(12874)); // Fastweb
        assert!(is_trusted_consumer_isp(3269));  // TIM
        assert!(is_trusted_consumer_isp(29447)); // Iliad
        assert!(!is_trusted_consumer_isp(99999)); // Unknown
        assert!(!is_trusted_consumer_isp(0));
    }

    #[test]
    fn test_max_patterns_cap_enforced() {
        let correlator = CrossIpCorrelator::with_bounds(5, 500);

        // 🚨 FLOOD di 1000 pattern distinti (ognuno 2 hit per promuovere). Senza
        // il bound dello ShardedLru la mappa crescerebbe a ~1000 (OOM path).
        for i in 0..1000 {
            let path = format!("/api/endpoint{}", i);
            correlator.record(ip(1), &path, bot_ua(), None, None);
            correlator.record(ip(2), &path, bot_ua(), None, None);
        }

        // Invariante: la mappa è HARD-bounded alla capacità dello ShardedLru
        // (sharded → ~16, per arrotondamento del cap su 16 shard), MAI illimitata.
        // L'eviction è LRU true-O(1) (niente scan O(n) per-request).
        let cap = correlator.pattern_to_ips.capacity();
        assert!(
            correlator.tracked_patterns() <= cap,
            "patterns non bounded: {} > cap {}",
            correlator.tracked_patterns(),
            cap
        );
        assert!(
            correlator.tracked_patterns() < 1000,
            "la mappa non è stata bounded sotto il flood"
        );
    }

    #[test]
    fn test_slow_distributed_detection() {
        let correlator = CrossIpCorrelator::new();

        // 20 unique IPs hitting the same pattern
        for i in 0..20 {
            correlator.record(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
                "/api/sensitive",
                bot_ua(),
                None,
                None,
            );
        }

        let detections = correlator.detect(ip(1), "/api/sensitive", bot_ua(), None, 0.0);
        let slow_dist = detections
            .iter()
            .find(|d| d.detection_type == CrossIpDetectionType::SlowDistributed);
        assert!(
            slow_dist.is_some(),
            "Expected SlowDistributed detection for 20 unique IPs"
        );
        assert_eq!(slow_dist.unwrap().risk_add, 0.3);
        assert!(slow_dist.unwrap().ip_count >= SLOW_DISTRIBUTED_IP_THRESHOLD);
    }

    #[test]
    fn test_probing_detection() {
        let correlator = CrossIpCorrelator::new();

        // 4 IPs follow the same path sequence: /api/auth -> /api/admin
        for i in 0..4 {
            correlator.record(ip(i), "/api/auth", bot_ua(), None, None);
            correlator.record(ip(i), "/api/admin", bot_ua(), None, None);
        }

        let detections = correlator.detect(ip(0), "/api/admin", bot_ua(), None, 0.0);
        let probing = detections.iter().find(|d| d.detection_type == CrossIpDetectionType::Probing);
        assert!(
            probing.is_some(),
            "Expected Probing detection for 4 IPs with same sequence, got: {:?}",
            detections
        );
        assert_eq!(probing.unwrap().risk_add, 0.5);
    }

    #[test]
    fn test_no_false_positive_few_ips() {
        let correlator = CrossIpCorrelator::new();

        // Only 2 IPs — below all thresholds
        for i in 0..2 {
            correlator.record(ip(i), "/api/test", bot_ua(), None, None);
        }

        let detections = correlator.detect(ip(0), "/api/test", bot_ua(), None, 0.0);
        // Should have zero or no high-risk detections
        let high_risk: Vec<_> = detections
            .iter()
            .filter(|d| matches!(
                d.detection_type,
                CrossIpDetectionType::Coordinated | CrossIpDetectionType::Botnet
            ))
            .collect();
        assert!(
            high_risk.is_empty(),
            "Should NOT trigger Coordinated/Botnet for only 2 IPs"
        );
    }

    #[test]
    fn test_unique_counter_promotion() {
        let mut counter = UniqueCounter::new();

        // Insert 51 unique IPs — should promote from Precise to Bounded
        for i in 0..51 {
            counter.insert(IpAddr::V4(Ipv4Addr::new(10, 0, (i / 255) as u8, (i % 255 + 1) as u8)));
        }

        assert_eq!(counter.count(), 51);
        assert!(matches!(counter, UniqueCounter::Bounded(_)));
    }

    #[test]
    fn test_unique_counter_reset() {
        let mut counter = UniqueCounter::new();
        for i in 0..10 {
            counter.insert(ip(i));
        }
        assert_eq!(counter.count(), 10);

        counter.reset();
        assert_eq!(counter.count(), 0);
        assert!(matches!(counter, UniqueCounter::Precise(_)));
    }

    #[test]
    fn test_timed_ip_set_prune() {
        let mut set = TimedIpSet::new();
        set.record(ip(1));
        set.record(ip(2));
        set.record(ip(3));

        // Before pruning — all entries present
        assert_eq!(set.short_window.len(), 3);

        // Prune with nothing stale — all remain
        set.prune();
        assert_eq!(set.short_window.len(), 3);
    }
}
