//! Cross-IP Behavioral Graph (WI-8)
//!
//! In-memory sharded graph that discovers botnet patterns invisible to
//! per-request analysis:
//! - Sybil: many IPs share the same UA hash
//! - Distributed Probe: many IPs hit the same rare path
//! - Coordinated Timing: cluster of IPs with near-identical request intervals
//!
//! Only IPs with risk_score > 10 enter the graph (sampling threshold).
//! Mappe `ShardedLru`: LRU eviction true-O(1) (bound HARD realtime, MAX_TRACKED_IPS),
//! reclaim degli stale su finestra 1h, set inversi cappati (anti-leak Sybil).

use sentinel_core::sharded_lru::ShardedLru;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Cap HARD del numero di IP tracciati (per mappa IP-keyed). `ShardedLru` evicta la
/// LRU in O(1) all'inserimento → bound REALE in tempo reale (il doc storico prometteva
/// "LRU eviction" che NON era implementata: era un retain-by-stale con cap soft enforced
/// solo nella cleanup periodica). ~64K IP elevated-risk simultanei è ben oltre il reale.
const MAX_TRACKED_IPS: usize = 64_000;
/// Cap HARD del numero di UA-hash tracciati nell'indice inverso Sybil.
const MAX_TRACKED_UAS: usize = 64_000;
/// Cap del set inverso IP-per-UA. La Sybil scatta a >15: 4096 è abbondante per rilevarla
/// e bounda la RAM (pre-fix `global_ua_to_ips` non aveva ALCUNA cleanup → leak: un
/// attaccante con 1 UA + N IP gonfiava un singolo set all'infinito).
const MAX_IPS_PER_UA: usize = 4096;
/// Cap del set di UA-hash per IP (bound della RAM per-IP, GEMELLO simmetrico di
/// `MAX_IPS_PER_UA`). Lo User-Agent è un header attacker-controlled (valori infiniti) e
/// `record()` gira per gli IP a rischio elevato → senza cap un SINGOLO IP che ruota
/// milioni di UA gonfia `ip_to_ua[ip]` all'infinito (OOM, BG1). `ShardedLru` cappa il
/// NUMERO di IP, non la taglia del set-valore: cappare la chiave non basta.
const MAX_UAS_PER_IP: usize = 1024;
/// Cap del set di path per IP (bound della RAM per-IP).
const MAX_PATHS_PER_IP: usize = 1024;
const WINDOW: Duration = Duration::from_secs(3600); // 1 hour

/// Timing profile for an IP
#[derive(Debug, Clone)]
struct TimingProfile {
    /// Recent request timestamps (last 20)
    timestamps: VecDeque<Instant>,
    /// Last seen
    last_seen: Instant,
}

impl TimingProfile {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::with_capacity(20),
            last_seen: Instant::now(),
        }
    }

    fn record(&mut self) {
        let now = Instant::now();
        self.last_seen = now;
        self.timestamps.push_back(now);
        if self.timestamps.len() > 20 {
            self.timestamps.pop_front();
        }
    }

    // (rimosso avg_interval_ms: dead_code mai chiamato. interval_stddev_ms qui sotto è il
    //  metodo di timing realmente usato.)

    /// Standard deviation of inter-request intervals in ms
    fn interval_stddev_ms(&self) -> Option<f64> {
        if self.timestamps.len() < 3 {
            return None;
        }

        let intervals: Vec<f64> = self.timestamps
            .iter()
            .zip(self.timestamps.iter().skip(1))
            .map(|(a, b)| b.duration_since(*a).as_millis() as f64)
            .collect();

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        Some(variance.sqrt())
    }

    fn is_stale(&self) -> bool {
        self.last_seen.elapsed() > WINDOW
    }

    /// Feature di timing per il threat_classifier: (burst_score, inter_request_stddev_ms).
    /// burst = numero di richieste nell'ultimo secondo (raffica); stddev = deviazione standard
    /// degli intervalli inter-richiesta (bassa = automazione). Valori REALI dai timestamp.
    fn timing_features(&self) -> (f32, f32) {
        let now = Instant::now();
        let burst = self
            .timestamps
            .iter()
            .filter(|t| now.duration_since(**t) <= Duration::from_secs(1))
            .count() as f32;
        let stddev = self.interval_stddev_ms().unwrap_or(0.0) as f32;
        (burst, stddev)
    }
}

/// Detection result from the behavioral graph
#[derive(Debug, Clone)]
pub struct GraphDetection {
    /// Type of pattern detected
    pub pattern: GraphPattern,
    /// Risk points to add
    pub risk_points: i32,
    /// Details for logging
    pub detail: String,
}

/// Types of patterns detected by the graph
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphPattern {
    /// Many IPs share the same UA
    Sybil,
    /// Many IPs hitting the same rare path
    DistributedProbe,
    /// Cluster of IPs with synchronized timing
    CoordinatedTiming,
}

/// Cross-IP Behavioral Graph.
///
/// Tutte le mappe sono `ShardedLru` (sharding interno seed-randomizzato + LRU true-O(1)):
/// bound HARD della memoria in tempo reale. `global_ua_to_ips` è l'indice inverso per la
/// Sybil-detection: l'LRU sull'outer è semanticamente OK perché un attaccante Sybil ATTIVO
/// mantiene la sua UA recente (ogni IP del botnet la "tocca") → non viene sfrattata; il set
/// inner è cappato (`MAX_IPS_PER_UA`, ≫ soglia 15) → memoria bounded senza perdere il segnale.
pub struct BehaviorGraph {
    /// IP → set of UA hashes used by this IP
    ip_to_ua: ShardedLru<IpAddr, HashSet<u64>>,
    /// IP → set of normalized path patterns
    ip_to_paths: ShardedLru<IpAddr, HashSet<String>>,
    /// IP → timing profile
    ip_timing: ShardedLru<IpAddr, TimingProfile>,
    /// Global UA → IPs reverse index (Sybil detection)
    global_ua_to_ips: ShardedLru<u64, HashSet<IpAddr>>,
}

impl BehaviorGraph {
    pub fn new() -> Self {
        Self {
            ip_to_ua: ShardedLru::new(MAX_TRACKED_IPS),
            ip_to_paths: ShardedLru::new(MAX_TRACKED_IPS),
            ip_timing: ShardedLru::new(MAX_TRACKED_IPS),
            global_ua_to_ips: ShardedLru::new(MAX_TRACKED_UAS),
        }
    }

    /// Record a request in the graph (only for IPs with elevated risk).
    /// Ogni `with_entry_mut` fa get-or-create + evict LRU O(1) se lo shard è pieno.
    pub fn record(&self, ip: IpAddr, ua_hash: u64, path: &str) {
        // IP → UA mapping. Set inner cappato anti-leak (BG1): l'UA è attacker-controlled.
        self.ip_to_ua.with_entry_mut(ip, HashSet::new, |uas| {
            if uas.len() < MAX_UAS_PER_IP {
                uas.insert(ua_hash);
            }
        });

        // UA → IP reverse mapping (Sybil). Set inner cappato anti-leak.
        self.global_ua_to_ips.with_entry_mut(ua_hash, HashSet::new, |ips| {
            if ips.len() < MAX_IPS_PER_UA {
                ips.insert(ip);
            }
        });

        // IP → paths. Set inner cappato anti-leak.
        self.ip_to_paths.with_entry_mut(ip, HashSet::new, |paths| {
            if paths.len() < MAX_PATHS_PER_IP {
                paths.insert(path.to_string());
            }
        });

        // IP timing
        self.ip_timing
            .with_entry_mut(ip, TimingProfile::new, |t| t.record());
    }

    /// Feature di timing per-IP (burst_score, inter_request_stddev_ms) per il threat_classifier.
    /// `(0.0, 0.0)` se l'IP non è tracciato. Il guard `contains` evita di creare un profilo
    /// vuoto sugli IP mai visti (read-only di fatto).
    pub fn timing_features(&self, ip: IpAddr) -> (f32, f32) {
        if !self.ip_timing.contains(&ip) {
            return (0.0, 0.0);
        }
        let mut out = (0.0_f32, 0.0_f32);
        self.ip_timing
            .with_entry_mut(ip, TimingProfile::new, |t| out = t.timing_features());
        out
    }

    /// Detect cross-IP patterns for a given IP
    pub fn detect(&self, ip: IpAddr, ua_hash: u64) -> Vec<GraphDetection> {
        let mut detections = Vec::new();

        // 1. Sybil detection: many IPs using the SAME UA (peek: non promuove la recency).
        let sybil_count = self
            .global_ua_to_ips
            .with_peek(&ua_hash, |o| o.map_or(0, |ips| ips.len()));
        if sybil_count > 15 {
            detections.push(GraphDetection {
                pattern: GraphPattern::Sybil,
                risk_points: 20,
                detail: format!("{} IPs share UA hash {:016x}", sybil_count, ua_hash),
            });
        }

        // 2. Coordinated timing: IPs with very low interval stddev.
        let timing = self.ip_timing.with_peek(&ip, |o| {
            o.and_then(|t| t.interval_stddev_ms().map(|sd| (sd, t.timestamps.len())))
        });
        if let Some((stddev, samples)) = timing {
            // Very low stddev (< 50ms) across 5+ requests = automation
            if stddev < 50.0 && samples >= 5 {
                detections.push(GraphDetection {
                    pattern: GraphPattern::CoordinatedTiming,
                    risk_points: 25,
                    detail: format!("Timing stddev={stddev:.1}ms across {samples} requests"),
                });
            }
        }

        detections
    }

    /// Periodic RECLAIM (call from background task). Il bound è strutturale in `ShardedLru`;
    /// qui si libera RAM: stale per finestra 1h + entry inverse di IP non più attivi.
    pub fn cleanup(&self) {
        self.ip_timing.retain(|_, profile| !profile.is_stale());

        // IP ancora attivi (presenti in ip_timing dopo il reclaim stale).
        let mut active: HashSet<IpAddr> = HashSet::new();
        self.ip_timing.for_each_mut(|ip, _| {
            active.insert(*ip);
        });
        self.ip_to_ua.retain(|ip, _| active.contains(ip));
        self.ip_to_paths.retain(|ip, _| active.contains(ip));
        // Igiene dell'indice Sybil: via i set rimasti vuoti (il bound è già strutturale).
        self.global_ua_to_ips.retain(|_, ips| !ips.is_empty());
    }

    /// Total tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.ip_timing.len()
    }
}

impl Default for BehaviorGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn timing_features_reali_per_ip_e_zero_se_assente() {
        let graph = BehaviorGraph::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        // IP mai visto → (0,0) e NON crea un profilo (read-only via contains-guard).
        assert_eq!(graph.timing_features(ip), (0.0, 0.0));
        assert!(!graph.ip_timing.contains(&ip), "non deve creare profilo per IP assente");

        // 4 richieste rapide → burst conta quelle nell'ultimo secondo (tutte) = 4.
        for _ in 0..4 {
            graph.record(ip, 0xAA, "/x");
        }
        let (burst, stddev) = graph.timing_features(ip);
        assert_eq!(burst, 4.0, "burst = richieste nell'ultimo secondo");
        assert!(stddev.is_finite() && stddev >= 0.0, "stddev finito e non-negativo: {stddev}");
    }

    #[test]
    fn test_sybil_detection() {
        let graph = BehaviorGraph::new();
        let ua_hash = 0xDEADBEEF;

        // 20 different IPs with the same UA
        for i in 0..20 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            graph.record(ip, ua_hash, "/api/test");
        }

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let detections = graph.detect(ip, ua_hash);
        assert!(detections.iter().any(|d| d.pattern == GraphPattern::Sybil));
    }

    #[test]
    fn test_no_false_positive_few_ips() {
        let graph = BehaviorGraph::new();
        let ua_hash = 0xCAFEBABE;

        // Only 3 IPs — should NOT trigger Sybil
        for i in 0..3 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            graph.record(ip, ua_hash, "/api/test");
        }

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let detections = graph.detect(ip, ua_hash);
        assert!(detections.is_empty());
    }

    #[test]
    fn test_cleanup() {
        let graph = BehaviorGraph::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        graph.record(ip, 123, "/test");
        assert_eq!(graph.tracked_ips(), 1);

        graph.cleanup();
        // Entry should still be there (not stale yet)
        assert_eq!(graph.tracked_ips(), 1);
    }

    /// 🚨 OOM/LEAK: tutte le mappe sono bounded realtime (`ShardedLru`) e il set inverso
    /// Sybil è cappato (anti-leak) SENZA perdere la rilevazione. Pre-fix: `global_ua_to_ips`
    /// non aveva ALCUNA cleanup (leak illimitato per-UA) + per-shard cap solo periodico.
    #[test]
    fn maps_bounded_and_sybil_preserved_under_flood() {
        // cap multipli dei 16 shard → capacity()==cap (costruzione diretta: campi nel modulo).
        let graph = BehaviorGraph {
            ip_to_ua: ShardedLru::new(64),
            ip_to_paths: ShardedLru::new(64),
            ip_timing: ShardedLru::new(64),
            global_ua_to_ips: ShardedLru::new(64),
        };
        let ua = 0xBADC0FFEE0DDF00D;
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(10, b[1], b[2], b[3]));
            graph.record(ip, ua, "/x");
        }
        // ip_timing bounded ESATTAMENTE al cap (5000 IP distinti → ogni shard satura).
        assert_eq!(
            graph.tracked_ips(),
            64,
            "ip_timing non bounded realtime (got {})",
            graph.tracked_ips()
        );
        // Indice Sybil: 1 sola UA → set inner cappato a MAX_IPS_PER_UA (anti-leak).
        // Mutation-verify: togliendo il cap `ips.len() < MAX_IPS_PER_UA` → inner == 5000.
        let inner = graph
            .global_ua_to_ips
            .with_peek(&ua, |o| o.map_or(0, |s| s.len()));
        assert_eq!(inner, MAX_IPS_PER_UA, "set Sybil inner non cappato (got {inner})");
        // Sybil ANCORA rilevata nonostante il cap (count ≫ soglia 15).
        let det = graph.detect(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), ua);
        assert!(
            det.iter().any(|d| d.pattern == GraphPattern::Sybil),
            "Sybil deve restare rilevabile sotto il cap del set inner"
        );
    }

    /// 🚨 BG1 (OOM, gemello SIMMETRICO di MAX_IPS_PER_UA): il set inner `ip_to_ua[ip]`
    /// (UA-hash per IP) è cappato. L'UA è un header attacker-controlled (valori infiniti)
    /// e `record()` gira per gli IP a rischio elevato → un SINGOLO IP che ruota milioni di
    /// UA gonfierebbe il set all'infinito (OOM). `ShardedLru` cappa il NUMERO di IP, non la
    /// taglia del set-valore. Mutation-verify: togliendo `uas.len() < MAX_UAS_PER_IP` →
    /// inner == 5000.
    #[test]
    fn ip_to_ua_inner_set_capped_under_ua_rotation() {
        let graph = BehaviorGraph::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9));
        for ua in 0..5000u64 {
            graph.record(ip, ua, "/x");
        }
        let inner = graph.ip_to_ua.with_peek(&ip, |o| o.map_or(0, |s| s.len()));
        assert_eq!(
            inner, MAX_UAS_PER_IP,
            "ip_to_ua inner set (UA-per-IP) non cappato (got {inner})"
        );
    }
}
