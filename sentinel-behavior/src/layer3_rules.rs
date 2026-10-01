//! SENTINEL Layer 3 — 5 hard behavioral rules (2026-06-02).
//!
//! Le rules sono pattern di abuso che il behavioral score weighted potrebbe
//! NON catturare individualmente. Ognuna emette un "strong signal"
//! (score >= 0.85) che, via update_level escape hatch in sentinel-core,
//! forza RiskLevel::High → Action::Ban.
//!
//! Rules:
//!   1. FourxxBurst   — >= 20 status 4xx/60s da singolo IP
//!   2. MultiUaPerIp  — >= 3 User-Agent distinct da singolo IP entro 5min
//!   3. FakeReferer   — Referer header dichiarato ma path-flow incoerente
//!   4. PathTraversalProbe — >= 5 path sospetti (/etc/passwd, ../../, %2e%2e) /min
//!   5. SlowDistributed — cross-IP coordinated low-rate (delegato a CrossIpCorrelator)
//!
//! Tutte sliding-window in-memory con DashMap (lock-free). Cleanup auto
//! ogni 5min via SentinelServer periodic cleanup.

use sentinel_core::sharded_lru::ShardedLru;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::collections::VecDeque;

/// Severity score per ogni rule (range 0.0 - 1.0).
/// >= 0.85 triggera l'escape hatch in update_level → forza RiskLevel::High.
const STRONG_SIGNAL_THRESHOLD: f64 = 0.85;

/// Sliding window per rule counters.
const WINDOW_4XX_BURST: Duration = Duration::from_secs(60);
/// F8 (2026-06-02): finestra medio termine — cattura slow-burn 1 hit/18s
const WINDOW_4XX_MID_BURN: Duration = Duration::from_secs(30 * 60); // 30 min
/// F8: finestra long-tail — cattura attaccanti molto pazienti (1 hit/7min)
const WINDOW_4XX_LONG_BURN: Duration = Duration::from_secs(24 * 60 * 60); // 24h
const WINDOW_MULTI_UA: Duration = Duration::from_secs(300);
const WINDOW_PATH_TRAVERSAL: Duration = Duration::from_secs(60);

/// Threshold per rule.
const THRESHOLD_4XX_BURST: usize = 20;
/// F8: mid-burn — 100 hit in 30min = ~1 hit/18s, evade 20/60s ma non questo
const THRESHOLD_4XX_MID_BURN: usize = 100;
/// F8: long-burn — 200 hit in 24h = attaccante paziente che testa lentamente
const THRESHOLD_4XX_LONG_BURN: usize = 200;
const THRESHOLD_MULTI_UA: usize = 3;
const THRESHOLD_PATH_TRAVERSAL: usize = 5;

/// Cap HARD dei deque hits 4xx per-IP (anti-OOM, classe EL1-B). ≫ THRESHOLD_4XX_LONG_BURN
/// (200) → la detection (che confronta col threshold) non è alterata.
const MAX_4XX_HITS: usize = 512;
/// Cap HARD del deque uas per-IP (anti-OOM, classe EL1-B). ≫ THRESHOLD_MULTI_UA (3).
const MAX_UA_SAMPLES: usize = 256;
/// Cap HARD del numero di IP tracciati per-mappa (anti-OOM/SESSION1): IP attacker-controlled.
const MAX_LAYER3_IPS: usize = 50_000;

/// Detection result emesso da una rule. Convertito in JSONL event LoRA-ready
/// + applicato come boost al behavioral_score.
#[derive(Debug, Clone, Serialize)]
pub struct RuleDetection {
    /// F6: monotonic per-process ID for LoRA JSONL pipeline (since-cursor support)
    pub event_id: u64,
    /// F6: epoch seconds when the detection fired
    pub detected_at_epoch_secs: u64,
    pub rule_id: &'static str,
    pub severity_score: f64,
    pub ip: String,
    pub evidence_count: usize,
    pub time_window_sec: u64,
    pub human_description: String,
    pub decision_label: &'static str,
}

/// Per-IP sliding-window state per rule 1 (4xx burst).
/// F8 (2026-06-02): mantiene 3 deque separate per finestra (60s, 30min, 24h).
/// Memoria worst-case per IP: 200 Instant (16 byte each) = 3.2 KiB.
/// Con cleanup periodico le entry vecchie vengono potate.
#[derive(Default)]
struct FourxxState {
    hits: VecDeque<Instant>,
    hits_mid: VecDeque<Instant>,
    hits_long: VecDeque<Instant>,
}

/// Per-IP state per rule 2 (multi-UA).
#[derive(Default)]
struct MultiUaState {
    uas: VecDeque<(Instant, u64)>, // (time, ua_hash)
}

/// Per-IP state per rule 4 (path traversal).
#[derive(Default)]
struct PathTraversalState {
    hits: VecDeque<Instant>,
}

/// Layer3 rules tracker. Thread-safe via DashMap.
pub struct Layer3Rules {
    /// Le 3 mappe per-IP sono `ShardedLru` (IP-keyed attacker-controlled → bound HARD
    /// realtime, evict LRU O(1)). Pre-fix: DashMap con cap enforced solo nel
    /// cleanup_expired periodico (retain by-time) → crescita illimitata fra le cleanup.
    fourxx: ShardedLru<IpAddr, FourxxState>,
    multi_ua: ShardedLru<IpAddr, MultiUaState>,
    path_traversal: ShardedLru<IpAddr, PathTraversalState>,
    /// Total rule triggers (for metrics).
    pub trigger_count: Arc<AtomicU64>,
    /// F6: monotonic event id counter for LoRA pipeline
    event_seq: Arc<AtomicU64>,
}

impl Layer3Rules {
    pub fn new() -> Self {
        Self {
            fourxx: ShardedLru::new(MAX_LAYER3_IPS),
            multi_ua: ShardedLru::new(MAX_LAYER3_IPS),
            path_traversal: ShardedLru::new(MAX_LAYER3_IPS),
            trigger_count: Arc::new(AtomicU64::new(0)),
            event_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// F6: next monotonic event id (consumed per detection)
    fn next_event_id(&self) -> u64 {
        self.event_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// F6: epoch seconds helper for detected_at_epoch_secs
    fn epoch_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Convenience for tests + external callers — alias of cleanup_expired(Instant::now()).
    pub fn cleanup(&self) {
        self.cleanup_expired(Instant::now());
    }

    /// Cleanup expired entries — chiamato periodicamente da SentinelServer.
    pub fn cleanup_expired(&self, now: Instant) {
        // 4xx burst — F8: 3 finestre (60s / 30min / 24h)
        self.fourxx.retain(|_, state| {
            while let Some(t) = state.hits.front() {
                if now.duration_since(*t) > WINDOW_4XX_BURST {
                    state.hits.pop_front();
                } else { break; }
            }
            while let Some(t) = state.hits_mid.front() {
                if now.duration_since(*t) > WINDOW_4XX_MID_BURN {
                    state.hits_mid.pop_front();
                } else { break; }
            }
            while let Some(t) = state.hits_long.front() {
                if now.duration_since(*t) > WINDOW_4XX_LONG_BURN {
                    state.hits_long.pop_front();
                } else { break; }
            }
            !state.hits.is_empty() || !state.hits_mid.is_empty() || !state.hits_long.is_empty()
        });

        // Multi-UA
        self.multi_ua.retain(|_, state| {
            while let Some((t, _)) = state.uas.front() {
                if now.duration_since(*t) > WINDOW_MULTI_UA {
                    state.uas.pop_front();
                } else { break; }
            }
            !state.uas.is_empty()
        });

        // Path traversal
        self.path_traversal.retain(|_, state| {
            while let Some(t) = state.hits.front() {
                if now.duration_since(*t) > WINDOW_PATH_TRAVERSAL {
                    state.hits.pop_front();
                } else { break; }
            }
            !state.hits.is_empty()
        });
    }

    /// Rule 1 + F8 1b/1c: record a 4xx response per IP, check 3 sliding windows.
    /// - Fast (60s): 20+ hit → bot brute-force aggressivo
    /// - Mid (30min): 100+ hit → slow-burn evader (1 hit/18s)
    /// - Long (24h): 200+ hit → attaccante paziente (1 hit/7min)
    /// Priorita\` di trigger: fast > mid > long (più stretto = più probative).
    pub fn record_4xx(&self, ip: IpAddr, status: u16) -> Option<RuleDetection> {
        if !(400..500).contains(&status) {
            return None;
        }
        let now = Instant::now();
        // `with_entry_mut`: get-or-create + evict LRU O(1) se lo shard è pieno (bound HARD
        // realtime). L'analisi (i `return Some(..)`) gira tutta dentro la closure.
        self.fourxx
            .with_entry_mut(ip, FourxxState::default, |state| self.analyze_fourxx(state, ip, now))
    }

    fn analyze_fourxx(
        &self,
        state: &mut FourxxState,
        ip: IpAddr,
        now: Instant,
    ) -> Option<RuleDetection> {
        // ── Cleanup expired in all 3 windows ──────────────────────────
        while let Some(t) = state.hits.front() {
            if now.duration_since(*t) > WINDOW_4XX_BURST {
                state.hits.pop_front();
            } else { break; }
        }
        while let Some(t) = state.hits_mid.front() {
            if now.duration_since(*t) > WINDOW_4XX_MID_BURN {
                state.hits_mid.pop_front();
            } else { break; }
        }
        while let Some(t) = state.hits_long.front() {
            if now.duration_since(*t) > WINDOW_4XX_LONG_BURN {
                state.hits_long.pop_front();
            } else { break; }
        }

        // Push to all 3 windows
        state.hits.push_back(now);
        state.hits_mid.push_back(now);
        state.hits_long.push_back(now);
        // Cap HARD (EL1-B): il time-prune per-finestra non bounda il COUNT sotto flood ad
        // alto rate. Le soglie (max THRESHOLD_4XX_LONG_BURN=200) sono ≪ MAX_4XX_HITS →
        // detection invariata; drop O(1) del più vecchio.
        while state.hits.len() > MAX_4XX_HITS {
            state.hits.pop_front();
        }
        while state.hits_mid.len() > MAX_4XX_HITS {
            state.hits_mid.pop_front();
        }
        while state.hits_long.len() > MAX_4XX_HITS {
            state.hits_long.pop_front();
        }

        let count_fast = state.hits.len();
        let count_mid = state.hits_mid.len();
        let count_long = state.hits_long.len();

        // ── Priority 1 (fast): aggressive bot 60s window ──────────────
        if count_fast >= THRESHOLD_4XX_BURST {
            self.trigger_count.fetch_add(1, Ordering::Relaxed);
            return Some(RuleDetection {
                event_id: self.next_event_id(),
                detected_at_epoch_secs: Self::epoch_now_secs(),
                rule_id: "behavioral.4xx_burst",
                severity_score: STRONG_SIGNAL_THRESHOLD,
                ip: ip.to_string(),
                evidence_count: count_fast,
                time_window_sec: WINDOW_4XX_BURST.as_secs(),
                human_description: format!(
                    "Un IP ha generato {} risposte 4xx in {} secondi — comportamento da scanner brute-force \
                     (cerca endpoint protetti, prova credenziali, sonda errori applicativi). Soglia: {} hit/min.",
                    count_fast, WINDOW_4XX_BURST.as_secs(), THRESHOLD_4XX_BURST,
                ),
                decision_label: "ban_immediate",
            });
        }

        // ── Priority 2 (mid-burn F8): slow-burn 100/30min ─────────────
        // Trigger SOLO se non già scattata fast window (per evitare doppio ban
        // sullo stesso comportamento). E solo al crossing della soglia, non
        // su ogni hit successivo (otherwise: spam detection).
        if count_mid == THRESHOLD_4XX_MID_BURN {
            self.trigger_count.fetch_add(1, Ordering::Relaxed);
            return Some(RuleDetection {
                event_id: self.next_event_id(),
                detected_at_epoch_secs: Self::epoch_now_secs(),
                rule_id: "behavioral.4xx_mid_burn",
                severity_score: STRONG_SIGNAL_THRESHOLD,
                ip: ip.to_string(),
                evidence_count: count_mid,
                time_window_sec: WINDOW_4XX_MID_BURN.as_secs(),
                human_description: format!(
                    "Un IP ha generato {} risposte 4xx in {} minuti — pattern slow-burn (~1 hit/{}s, sotto la \
                     soglia veloce 20/60s ma deliberato e sostenuto). Tipico di attaccanti che evadono rate-limit \
                     temporali stretti.",
                    count_mid,
                    WINDOW_4XX_MID_BURN.as_secs() / 60,
                    WINDOW_4XX_MID_BURN.as_secs() / count_mid.max(1) as u64,
                ),
                decision_label: "ban_immediate",
            });
        }

        // ── Priority 3 (long-burn F8): patient attacker 200/24h ───────
        if count_long == THRESHOLD_4XX_LONG_BURN {
            self.trigger_count.fetch_add(1, Ordering::Relaxed);
            return Some(RuleDetection {
                event_id: self.next_event_id(),
                detected_at_epoch_secs: Self::epoch_now_secs(),
                rule_id: "behavioral.4xx_long_burn",
                severity_score: STRONG_SIGNAL_THRESHOLD,
                ip: ip.to_string(),
                evidence_count: count_long,
                time_window_sec: WINDOW_4XX_LONG_BURN.as_secs(),
                human_description: format!(
                    "Un IP ha generato {} risposte 4xx in 24 ore — pattern long-burn (~1 hit ogni {} secondi). \
                     Attaccante molto paziente che evade tutte le finestre brevi ma cumulativamente persistente. \
                     Tipico di scanner deliberatamente low-and-slow.",
                    count_long,
                    WINDOW_4XX_LONG_BURN.as_secs() / count_long.max(1) as u64,
                ),
                decision_label: "ban_immediate",
            });
        }

        None
    }

    /// Rule 2: record a User-Agent for an IP. Triggers se >= 3 UA distinct in 5min.
    pub fn record_ua(&self, ip: IpAddr, ua: &str) -> Option<RuleDetection> {
        let ua_hash = hash_string(ua);
        let now = Instant::now();
        self.multi_ua.with_entry_mut(ip, MultiUaState::default, |state| {
            self.analyze_multi_ua(state, ip, ua_hash, now)
        })
    }

    fn analyze_multi_ua(
        &self,
        state: &mut MultiUaState,
        ip: IpAddr,
        ua_hash: u64,
        now: Instant,
    ) -> Option<RuleDetection> {
        // Cleanup expired
        while let Some((t, _)) = state.uas.front() {
            if now.duration_since(*t) > WINDOW_MULTI_UA {
                state.uas.pop_front();
            } else { break; }
        }
        state.uas.push_back((now, ua_hash));
        // Cap HARD (EL1-B): la soglia distinct (THRESHOLD_MULTI_UA=3) è ≪ MAX_UA_SAMPLES.
        while state.uas.len() > MAX_UA_SAMPLES {
            state.uas.pop_front();
        }

        // Count distinct hashes
        let mut distinct = std::collections::HashSet::new();
        for (_, h) in state.uas.iter() {
            distinct.insert(*h);
        }
        let distinct_count = distinct.len();

        if distinct_count >= THRESHOLD_MULTI_UA {
            self.trigger_count.fetch_add(1, Ordering::Relaxed);
            Some(RuleDetection {
                event_id: self.next_event_id(),
                detected_at_epoch_secs: Self::epoch_now_secs(),
                rule_id: "behavioral.multi_ua_per_ip",
                severity_score: STRONG_SIGNAL_THRESHOLD,
                ip: ip.to_string(),
                evidence_count: distinct_count,
                time_window_sec: WINDOW_MULTI_UA.as_secs(),
                human_description: format!(
                    "Un IP ha cambiato User-Agent {} volte in {} secondi — pattern tipico di scanner che \
                     ruota fingerprint per evadere rate limit / WAF. Browser reali NON cambiano UA così. \
                     Soglia: {} UA distinti/5min.",
                    distinct_count, WINDOW_MULTI_UA.as_secs(), THRESHOLD_MULTI_UA,
                ),
                decision_label: "ban_immediate",
            })
        } else { None }
    }

    /// Rule 3: fake-referer detection. Referer dichiarato esterno (no nostro
    /// domain) MA path NON è entrypoint legit (home, signup, login).
    pub fn record_referer(&self, ip: IpAddr, referer: Option<&str>, path: &str, our_origin: &str) -> Option<RuleDetection> {
        let ref_str = referer?;
        if ref_str.is_empty() { return None; }
        // Skip self-origin (legit navigation)
        if ref_str.contains(our_origin) { return None; }
        // Skip search engines (legit incoming)
        let legit_referers = ["google.com", "bing.com", "duckduckgo.com", "facebook.com", "linkedin.com", "twitter.com", "x.com", "t.co"];
        if legit_referers.iter().any(|s| ref_str.contains(s)) { return None; }
        // Path entrypoint legitimi
        let entry_paths = ["/", "/signup", "/login", "/pricing", "/docs", "/integrazioni", "/sicurezza", "/about"];
        if entry_paths.iter().any(|p| path == *p || path.starts_with(&format!("{p}/"))) {
            return None;
        }
        // Path applicativo profondo CON referer esterno NON-search = sospetto.
        // Esempio attacco: scanner POST /api/v1/admin/users dichiara Referer:
        // https://acme.com/page1 per provare CSRF bypass.
        self.trigger_count.fetch_add(1, Ordering::Relaxed);
        Some(RuleDetection {
            event_id: self.next_event_id(),
            detected_at_epoch_secs: Self::epoch_now_secs(),
            rule_id: "behavioral.fake_referer",
            severity_score: 0.5, // Mid score — referer fake è sospetto ma non sempre ban-worthy
            ip: ip.to_string(),
            evidence_count: 1,
            time_window_sec: 0,
            human_description: format!(
                "Un IP ha richiesto un endpoint profondo del sito ({}) dichiarando di arrivare da '{}', \
                 ma il path non è un entrypoint pubblico legitimo né un referrer da motore di ricerca/social. \
                 Pattern tipico di scanner che simula traffico organico per bypassare check CSRF.",
                path, ref_str.chars().take(80).collect::<String>(),
            ),
            decision_label: "monitor_increment_score",
        })
    }

    /// Rule 4: path traversal probe sequence — >= 5 path con encoded traversal in 60s
    /// SENZA aver triggerato honeypot (più subtle).
    pub fn record_path_traversal(&self, ip: IpAddr, path: &str) -> Option<RuleDetection> {
        let is_traversal = path.contains("..")
            || path.contains("%2e%2e")
            || path.contains("%252e")
            || path.contains("/etc/passwd")
            || path.contains("/proc/self")
            || path.contains("../../");
        if !is_traversal { return None; }

        let now = Instant::now();
        self.path_traversal.with_entry_mut(ip, PathTraversalState::default, |state| {
            self.analyze_path_traversal(state, ip, now)
        })
    }

    fn analyze_path_traversal(
        &self,
        state: &mut PathTraversalState,
        ip: IpAddr,
        now: Instant,
    ) -> Option<RuleDetection> {
        while let Some(t) = state.hits.front() {
            if now.duration_since(*t) > WINDOW_PATH_TRAVERSAL {
                state.hits.pop_front();
            } else { break; }
        }
        state.hits.push_back(now);
        let count = state.hits.len();

        if count >= THRESHOLD_PATH_TRAVERSAL {
            self.trigger_count.fetch_add(1, Ordering::Relaxed);
            Some(RuleDetection {
                event_id: self.next_event_id(),
                detected_at_epoch_secs: Self::epoch_now_secs(),
                rule_id: "behavioral.path_traversal_probe",
                severity_score: STRONG_SIGNAL_THRESHOLD,
                ip: ip.to_string(),
                evidence_count: count,
                time_window_sec: WINDOW_PATH_TRAVERSAL.as_secs(),
                human_description: format!(
                    "Un IP ha provato {} path con pattern di directory traversal in {} secondi (es. \
                     '../../', '%2e%2e', '/etc/passwd', '/proc/self'). Sta cercando vulnerabilità di file \
                     inclusion o path traversal. Soglia: {} probe/min.",
                    count, WINDOW_PATH_TRAVERSAL.as_secs(), THRESHOLD_PATH_TRAVERSAL,
                ),
                decision_label: "ban_immediate",
            })
        } else { None }
    }

    /// Rule 5: slow-distributed signature — bridge a CrossIpCorrelator existing.
    /// Triggered esternamente dal cross_ip module quando rileva botnet/distributed.
    pub fn record_cross_ip_signature(&self, ip: IpAddr, pattern_type: &str, evidence_count: usize) -> RuleDetection {
        self.trigger_count.fetch_add(1, Ordering::Relaxed);
        RuleDetection {
            event_id: self.next_event_id(),
            detected_at_epoch_secs: Self::epoch_now_secs(),
            rule_id: "behavioral.slow_distributed",
            severity_score: 0.90, // High — coordinated attacks sono critici
            ip: ip.to_string(),
            evidence_count,
            time_window_sec: 600, // Cross-IP correlator usa finestra 10min
            human_description: format!(
                "Un cluster di {} IP coordinati ha mostrato il pattern '{}' — botnet o attacco distribuito \
                 a basso rate (per evadere rate limit per-IP). Ogni IP da solo sembra innocuo, ma il \
                 comportamento aggregato rivela coordinazione.",
                evidence_count, pattern_type,
            ),
            decision_label: "ban_immediate",
        }
    }

    /// Numero IP tracciati (per metrics dashboard).
    pub fn tracked_ips(&self) -> usize {
        self.fourxx.len() + self.multi_ua.len() + self.path_traversal.len()
    }
}

impl Default for Layer3Rules {
    fn default() -> Self { Self::new() }
}

fn hash_string(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(o: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(1, 2, 3, o)) }

    /// 🚨 SESSION1/OOM: le 3 mappe per-IP (fourxx/multi_ua/path_traversal) sono bounded
    /// realtime via ShardedLru (evict LRU O(1)), non più via il cleanup_expired periodico
    /// (retain by-time). Mutation-verify: revert a DashMap → len == 5000 invece di == cap.
    #[test]
    fn layer3_maps_bounded_realtime_under_ip_flood() {
        let cap = 64; // multiplo dei 16 shard → capacity()==64
        let r = Layer3Rules {
            fourxx: ShardedLru::new(cap),
            multi_ua: ShardedLru::new(cap),
            path_traversal: ShardedLru::new(cap),
            trigger_count: Arc::new(AtomicU64::new(0)),
            event_seq: Arc::new(AtomicU64::new(0)),
        };
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, b[2], b[3])); // 5000 IP distinti
            let _ = r.record_4xx(addr, 404);
            let _ = r.record_ua(addr, "ua-x");
            let _ = r.record_path_traversal(addr, "/../../etc/passwd");
        }
        assert_eq!(r.fourxx.len(), cap, "fourxx non bounded (got {})", r.fourxx.len());
        assert_eq!(r.multi_ua.len(), cap, "multi_ua non bounded (got {})", r.multi_ua.len());
        assert_eq!(
            r.path_traversal.len(),
            cap,
            "path_traversal non bounded (got {})",
            r.path_traversal.len()
        );
    }

    // ─── Rule 1: 4xx burst ─────────────────────────────────────────────
    #[test]
    fn rule1_4xx_burst_under_threshold_no_trigger() {
        let r = Layer3Rules::new();
        for _ in 0..19 {
            assert!(r.record_4xx(ip(1), 404).is_none());
        }
    }

    #[test]
    fn rule1_4xx_burst_at_threshold_triggers() {
        let r = Layer3Rules::new();
        let mut det = None;
        for _ in 0..20 {
            det = r.record_4xx(ip(1), 404);
        }
        let d = det.expect("rule should trigger at threshold");
        assert_eq!(d.rule_id, "behavioral.4xx_burst");
        assert_eq!(d.evidence_count, 20);
        assert!(d.severity_score >= 0.85);
        assert!(d.human_description.contains("20"));
        assert_eq!(d.decision_label, "ban_immediate");
    }

    #[test]
    fn rule1_4xx_only_4xx_status_counts() {
        let r = Layer3Rules::new();
        for _ in 0..30 {
            assert!(r.record_4xx(ip(2), 200).is_none(), "2xx must NOT trigger");
            assert!(r.record_4xx(ip(2), 500).is_none(), "5xx must NOT trigger");
        }
    }

    #[test]
    fn rule1_4xx_per_ip_isolated() {
        let r = Layer3Rules::new();
        for _ in 0..19 {
            r.record_4xx(ip(1), 404);
        }
        // IP diverso non triggera (state isolato)
        for _ in 0..5 {
            assert!(r.record_4xx(ip(2), 404).is_none());
        }
    }

    // ─── Rule 2: multi-UA per IP ───────────────────────────────────────
    #[test]
    fn rule2_multi_ua_2_distinct_no_trigger() {
        let r = Layer3Rules::new();
        r.record_ua(ip(1), "Mozilla/5.0 Chrome/131");
        let det = r.record_ua(ip(1), "Mozilla/5.0 Firefox/131");
        assert!(det.is_none(), "2 distinct UA should not trigger (threshold=3)");
    }

    #[test]
    fn rule2_multi_ua_3_distinct_triggers() {
        let r = Layer3Rules::new();
        r.record_ua(ip(1), "Mozilla/5.0 Chrome/131");
        r.record_ua(ip(1), "Mozilla/5.0 Firefox/131");
        let det = r.record_ua(ip(1), "curl/8.5.0");
        let d = det.expect("3 distinct UA must trigger");
        assert_eq!(d.rule_id, "behavioral.multi_ua_per_ip");
        assert_eq!(d.evidence_count, 3);
        assert_eq!(d.decision_label, "ban_immediate");
    }

    #[test]
    fn rule2_multi_ua_same_ua_repeated_no_trigger() {
        let r = Layer3Rules::new();
        for _ in 0..50 {
            assert!(r.record_ua(ip(1), "Mozilla/5.0 Chrome/131").is_none());
        }
    }

    // ─── Rule 3: fake referer ──────────────────────────────────────────
    #[test]
    fn rule3_no_referer_no_trigger() {
        let r = Layer3Rules::new();
        assert!(r.record_referer(ip(1), None, "/api/v1/admin/users", "app.example.com").is_none());
    }

    #[test]
    fn rule3_self_referer_no_trigger() {
        let r = Layer3Rules::new();
        assert!(r.record_referer(
            ip(1),
            Some("https://app.example.com/dashboard"),
            "/api/v1/account",
            "app.example.com",
        ).is_none());
    }

    #[test]
    fn rule3_google_referer_legit() {
        let r = Layer3Rules::new();
        assert!(r.record_referer(
            ip(1),
            Some("https://www.google.com/search?q=flowforge"),
            "/api/v1/auth/login",
            "app.example.com",
        ).is_none());
    }

    #[test]
    fn rule3_external_referer_to_entry_path_no_trigger() {
        let r = Layer3Rules::new();
        // referer esterno → entry path (es. /signup, /pricing) = legit (sponsor/ads/blog post)
        assert!(r.record_referer(
            ip(1),
            Some("https://acme-blog.com/saas-list"),
            "/signup",
            "app.example.com",
        ).is_none());
    }

    #[test]
    fn rule3_external_referer_to_deep_api_path_triggers() {
        let r = Layer3Rules::new();
        let det = r.record_referer(
            ip(1),
            Some("https://attacker.com/page"),
            "/api/v1/admin/users",
            "app.example.com",
        );
        let d = det.expect("external→deep API should trigger");
        assert_eq!(d.rule_id, "behavioral.fake_referer");
        assert!(d.human_description.contains("/api/v1/admin/users"));
    }

    // ─── Rule 4: path traversal probe ──────────────────────────────────
    #[test]
    fn rule4_no_traversal_pattern_no_trigger() {
        let r = Layer3Rules::new();
        for _ in 0..10 {
            assert!(r.record_path_traversal(ip(1), "/api/v1/users").is_none());
        }
    }

    #[test]
    fn rule4_few_traversal_attempts_no_trigger() {
        let r = Layer3Rules::new();
        for _ in 0..4 {
            assert!(r.record_path_traversal(ip(1), "/../../etc/passwd").is_none());
        }
    }

    #[test]
    fn rule4_5_traversal_attempts_triggers() {
        let r = Layer3Rules::new();
        let paths = [
            "/../../etc/passwd",
            "/api/../../etc/shadow",
            "/files/%2e%2e%2fadmin",
            "/uploads/..%252fconfig",
            "/proc/self/environ",
        ];
        let mut det = None;
        for p in &paths {
            det = r.record_path_traversal(ip(1), p);
        }
        let d = det.expect("5 traversal probes must trigger");
        assert_eq!(d.rule_id, "behavioral.path_traversal_probe");
        assert_eq!(d.evidence_count, 5);
        assert!(d.severity_score >= 0.85);
        assert_eq!(d.decision_label, "ban_immediate");
    }

    // ─── F8: Rule 1b mid-burn slow-burn (100/30min) ────────────────────

    #[test]
    fn rule1b_mid_burn_below_fast_threshold_but_above_mid_triggers() {
        // Simula slow-burn: 100 hit, ma spalmati abbastanza da NON triggerare
        // la fast window (20/60s). 100 hit istantanei trigger ENTRAMBE le
        // finestre — la fast scatta PRIMA per priorità → rule_id=fast.
        // Questo test verifica il comportamento: priorita\` fast > mid > long.
        let r = Layer3Rules::new();
        let mut det = None;
        for _ in 0..100 {
            det = r.record_4xx(ip(20), 404);
        }
        let d = det.expect("100 hit must trigger qualcosa");
        // Tutti i 100 hit sono nello stesso istante (testing) → fast window li
        // vede tutti → fast scatta al 20esimo. Mid avrebbe 100 ma fast win.
        // Quindi il LAST detection vede fast (scattata già al 20).
        assert_eq!(d.rule_id, "behavioral.4xx_burst", "fast window ha priorita\\`");
        assert!(d.evidence_count >= 20);
    }

    #[test]
    fn rule1b_mid_burn_triggers_at_exactly_100_when_fast_window_empty() {
        // Per testare la mid window in isolamento, dobbiamo aggirare la fast.
        // Iniettiamo direttamente 99 hit "vecchi" nella mid window (oltre 60s
        // fa, quindi fast window li ha già scartati). Il 100esimo hit reale
        // → fast count = 1, mid count = 100 → trigger mid.
        let r = Layer3Rules::new();
        let now = Instant::now();
        // Inietta 99 hit a t-90s (oltre WINDOW_4XX_BURST 60s, dentro WINDOW_4XX_MID_BURN 30min)
        let stale = now.checked_sub(Duration::from_secs(90)).unwrap();
        r.fourxx.with_entry_mut(ip(21), FourxxState::default, |state| {
            for _ in 0..99 {
                state.hits.push_back(stale);     // verranno potati dalla fast
                state.hits_mid.push_back(stale); // restano in mid (< 30min)
                state.hits_long.push_back(stale);
            }
        });
        // 100esimo hit: fast cleanup → 1 hit, mid → 100 → trigger rule 1b
        let det = r.record_4xx(ip(21), 404).expect("mid window must trigger at 100");
        assert_eq!(det.rule_id, "behavioral.4xx_mid_burn");
        assert_eq!(det.evidence_count, 100);
        assert_eq!(det.time_window_sec, 30 * 60);
        assert!(det.severity_score >= 0.85);
        assert!(det.human_description.contains("slow-burn") || det.human_description.contains("minut"));
        assert_eq!(det.decision_label, "ban_immediate");
    }

    #[test]
    fn rule1b_mid_burn_does_not_spam_after_crossing_threshold() {
        // Una volta scattata la mid (==100), il 101esimo hit NON deve
        // riemettere mid (perche\` usiamo == invece di >=).
        let r = Layer3Rules::new();
        let stale = Instant::now().checked_sub(Duration::from_secs(90)).unwrap();
        r.fourxx.with_entry_mut(ip(22), FourxxState::default, |state| {
            for _ in 0..99 {
                state.hits.push_back(stale);
                state.hits_mid.push_back(stale);
                state.hits_long.push_back(stale);
            }
        });
        let det1 = r.record_4xx(ip(22), 404).expect("100th hit triggers mid");
        assert_eq!(det1.rule_id, "behavioral.4xx_mid_burn");

        // 101esimo hit: mid count = 101, NON deve riemettere
        let det2 = r.record_4xx(ip(22), 404);
        assert!(det2.is_none(), "rule 1b non deve spammare dopo crossing");
    }

    // ─── F8: Rule 1c long-burn (200/24h) ───────────────────────────────

    #[test]
    fn rule1c_long_burn_triggers_at_200_with_other_windows_empty() {
        // Pre-popola 199 hit a t-2h (oltre fast 60s e oltre mid 30min,
        // dentro long 24h). 200esimo hit reale → solo long scatta.
        let r = Layer3Rules::new();
        let stale = Instant::now().checked_sub(Duration::from_secs(2 * 60 * 60)).unwrap();
        r.fourxx.with_entry_mut(ip(23), FourxxState::default, |state| {
            for _ in 0..199 {
                // hits + hits_mid sono stale e verranno scartati dal cleanup
                // hits_long resta (2h << 24h)
                state.hits.push_back(stale);
                state.hits_mid.push_back(stale);
                state.hits_long.push_back(stale);
            }
        });
        let det = r.record_4xx(ip(23), 404).expect("long window must trigger at 200");
        assert_eq!(det.rule_id, "behavioral.4xx_long_burn");
        assert_eq!(det.evidence_count, 200);
        assert_eq!(det.time_window_sec, 24 * 60 * 60);
        assert!(det.severity_score >= 0.85);
        assert!(det.human_description.contains("long-burn") || det.human_description.contains("paziente"));
    }

    #[test]
    fn rule1_priority_fast_over_mid_over_long() {
        // Quando TUTTE le 3 condizioni sono soddisfatte (= 200 hit
        // istantanei), la fast window scatta PRIMA → rule_id = burst.
        let r = Layer3Rules::new();
        let mut det = None;
        for _ in 0..200 {
            det = r.record_4xx(ip(24), 404);
        }
        let d = det.expect("200 hit must trigger");
        // Fast scatta al 20esimo → tutti i seguenti hit ritornano fast.
        // (None tornato solo se condition crossing in mid/long.)
        // Verifica priorita\`: fast vince sempre quando attivo.
        assert_eq!(d.rule_id, "behavioral.4xx_burst");
    }

    #[test]
    fn rule1_cleanup_expires_all_3_windows() {
        let r = Layer3Rules::new();
        r.record_4xx(ip(25), 404);
        assert_eq!(r.tracked_ips(), 1);
        // Avanza oltre WINDOW_4XX_LONG_BURN (24h) — tutte le 3 finestre scadono
        let future = Instant::now() + WINDOW_4XX_LONG_BURN + Duration::from_secs(1);
        r.cleanup_expired(future);
        assert_eq!(r.tracked_ips(), 0, "cleanup deve eliminare entry quando TUTTE le finestre sono vuote");
    }

    #[test]
    fn rule1_state_retains_long_window_when_fast_expires() {
        // Dopo 90s, fast window e\` vuota ma mid/long hanno ancora hit
        // → entry NON deve essere rimossa dal cleanup.
        let r = Layer3Rules::new();
        r.record_4xx(ip(26), 404);
        let after_fast = Instant::now() + WINDOW_4XX_BURST + Duration::from_secs(30);
        r.cleanup_expired(after_fast);
        assert_eq!(r.tracked_ips(), 1, "mid/long hold ancora il hit");
    }

    // ─── Rule 5: slow-distributed bridge ───────────────────────────────
    #[test]
    fn rule5_cross_ip_signature_creates_detection() {
        let r = Layer3Rules::new();
        let d = r.record_cross_ip_signature(ip(1), "coordinated_timing", 15);
        assert_eq!(d.rule_id, "behavioral.slow_distributed");
        assert_eq!(d.evidence_count, 15);
        assert!(d.severity_score >= 0.85);
        assert!(d.human_description.contains("cluster"));
        assert_eq!(d.decision_label, "ban_immediate");
    }

    // ─── Cleanup expired ───────────────────────────────────────────────
    #[test]
    fn cleanup_removes_expired_entries() {
        let r = Layer3Rules::new();
        r.record_4xx(ip(1), 404);
        assert_eq!(r.tracked_ips(), 1);

        // F8: ora ci sono 3 finestre (60s/30min/24h). Cleanup rimuove
        // l'entry solo se TUTTE sono vuote → avanza oltre la più lunga.
        let future = Instant::now() + WINDOW_4XX_LONG_BURN + Duration::from_secs(1);
        r.cleanup_expired(future);
        assert_eq!(r.tracked_ips(), 0);
    }

    // ─── Metrics counter ───────────────────────────────────────────────
    #[test]
    fn trigger_count_increments_on_detection() {
        let r = Layer3Rules::new();
        let initial = r.trigger_count.load(Ordering::Relaxed);
        for _ in 0..20 { r.record_4xx(ip(1), 404); }
        let after = r.trigger_count.load(Ordering::Relaxed);
        assert!(after > initial);
    }
}
