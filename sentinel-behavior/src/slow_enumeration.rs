//! Slow-enumeration detector — chi MAPPA la struttura/gli accessi reali del sito.
//!
//! # Cosa cattura (e cosa NO)
//! Complementare a honeypot e Rule-1, NON ridondante:
//!  - **honeypot** banna al primo hit su un path-ESCA (`/.env`, `/.git/config`…): prende
//!    gli attaccanti "scemi", quelli con intento ovvio. Questo detector NON li ri-guarda.
//!  - **Rule-1 (4xx burst)** conta il VOLUME di 4xx in finestra breve (≥20/60s): prende il
//!    brute-force veloce.
//!  - **questo** conta la **VARIETÀ**: un IP che colleziona molti path DISTINTI con un
//!    client-error di PROBING (401/403/404) in una finestra LARGA (15 min), anche a basso
//!    rate, **evitando le esche**. È il profilo di chi MAPPA la struttura reale e sonda
//!    gli accessi — il "coordinato sotto-rate" che sfugge sia all'honeypot sia alle soglie
//!    di volume.
//!
//! # Quali status (e perché non i 200)
//!  - **404** = il path non esiste → mapping della struttura.
//!  - **403** = esiste ma vietato → sta cercando cosa è accessibile.
//!  - **401** = serve auth → probing di endpoint protetti.
//!  - **200 NO**: la navigazione legittima genera 200 su tanti path diversi → sarebbe un
//!    falso positivo garantito. L'enumeration di risorse ESISTENTI (data harvesting
//!    `/users/1,2,3…`) è un pattern diverso (sequenziale), coperto dall'Intent detector.
//!  - **5xx NO**: errore del server, non intento del client.
//!
//! Conta la DIVERSITÀ dei path in errore-di-probing, non il volume né una lista di esche
//! (che si sovrapporrebbe all'honeypot).
//!
//! # Stato e limiti
//! Stato per-IP in `DashMap` (lock-free), bounded per IP e nel numero di IP, con eviction
//! degli idle. Clock INIETTABILE (`*_at(..., now)`) → finestre testabili in modo
//! deterministico, senza sleep. Il detector è PURO sui dati: non banna, non fa I/O — emette
//! un `EnumCandidate` che il chiamante traduce (in shadow-mode) in un threat-record.

use sentinel_core::sharded_lru::ShardedLru;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// ─── Soglie (conservative: shadow-mode → misuriamo prima di bannare) ─────────────

/// Finestra scorrevole entro cui si contano i path distinti in errore-di-probing.
const WINDOW: Duration = Duration::from_secs(15 * 60);
/// Numero minimo di path DISTINTI nella finestra per emettere un candidate.
/// 10: un utente reale non tocca 10 path 401/403/404 distinti; uno scanner che mappa sì.
const MIN_DISTINCT_PATHS: usize = 10;
/// Status HTTP che indicano PROBING (non esiste / vietato / serve auth). NON i 200/5xx.
const PROBE_STATUSES: [u16; 3] = [401, 403, 404];
/// Cap di path memorizzati per IP (anti-OOM). > soglia, così il segnale non si perde.
const MAX_PATHS_PER_IP: usize = 64;
/// Cap globale di IP tracciati (anti-OOM su flood di IP).
const MAX_TRACKED_IPS: usize = 50_000;
/// Un IP senza probing da oltre questo intervallo è evictabile.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Anti-spam: dopo aver emesso un candidate per un IP, non se ne emette un altro per
/// questo intervallo. Senza, un IP con 50 path genererebbe ~40 threat-record identici.
const REPORT_COOLDOWN: Duration = Duration::from_secs(15 * 60);
/// Ogni quante registrazioni si fa una passata di eviction degli IP idle.
const SWEEP_EVERY: u64 = 1024;
/// Quanti path includere nell'evidenza del candidate (per il threat-record). Cap, non tutti.
const EVIDENCE_PATH_CAP: usize = 20;

/// true se lo status è un client-error di PROBING che ci interessa (401/403/404).
#[inline]
fn is_probe_status(status: u16) -> bool {
    PROBE_STATUSES.contains(&status)
}

// ─── Output ──────────────────────────────────────────────────────────────────

/// Esito positivo: un IP ha superato la soglia di path-probing distinti nella finestra.
/// Il chiamante lo trasforma in un threat shadow (detection_source = sentinel_enumeration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumCandidate {
    /// Quanti path DISTINTI in errore-di-probing nella finestra (≥ MIN_DISTINCT_PATHS).
    pub distinct_count: usize,
    /// Campione dei path distinti (ordinato, capped a EVIDENCE_PATH_CAP) — evidenza.
    pub sample_paths: Vec<String>,
    /// Ampiezza della finestra in secondi (per la descrizione del threat).
    pub window_secs: u64,
}

// ─── Stato per-IP ──────────────────────────────────────────────────────────────

struct IpRecord {
    /// (path normalizzato, quando l'errore-di-probing è stato osservato). Bounded.
    hits: Vec<(String, Instant)>,
    last_activity: Instant,
    /// Quando è stato emesso l'ultimo candidate per questo IP (anti-spam cooldown).
    last_reported: Option<Instant>,
}

impl IpRecord {
    fn new(now: Instant) -> Self {
        Self { hits: Vec::with_capacity(MIN_DISTINCT_PATHS), last_activity: now, last_reported: None }
    }

    fn record(&mut self, path: String, now: Instant) {
        self.last_activity = now;
        // Bounded: oltre il cap, scarta il più vecchio (front). Vec piccolo (≤64) → ok.
        if self.hits.len() >= MAX_PATHS_PER_IP {
            self.hits.remove(0);
        }
        self.hits.push((path, now));
    }

    /// Path DISTINTI con timestamp dentro [now-window, now]. Ritorna i distinti ordinati.
    fn distinct_in_window(&self, window: Duration, now: Instant) -> Vec<String> {
        let cutoff = now.checked_sub(window);
        let mut set: HashSet<&str> = HashSet::new();
        for (p, t) in &self.hits {
            // `t >= cutoff` — se cutoff è None (now < window dall'avvio del processo)
            // tutto è dentro finestra.
            let in_window = cutoff.is_none_or(|c| *t >= c);
            if in_window {
                set.insert(p.as_str());
            }
        }
        let mut out: Vec<String> = set.into_iter().map(str::to_owned).collect();
        out.sort_unstable();
        out
    }
}

/// Normalizza un path per il conteggio dei distinti: niente query-string, lowercase,
/// trailing slash rimosso (≠ root). Così `/X?a=1` e `/x/` e `/x` contano come UNO.
fn normalize_path(path: &str) -> String {
    let no_query = path.split('?').next().unwrap_or(path);
    let lowered = no_query.to_lowercase();
    let trimmed = lowered.trim_end_matches('/');
    if trimmed.is_empty() { "/".to_owned() } else { trimmed.to_owned() }
}

// ─── Detector ──────────────────────────────────────────────────────────────────

/// Rileva enumeration lenta (varietà di path in errore-di-probing) per-IP.
/// Lock-free, bounded, no I/O.
pub struct SlowEnumerationDetector {
    /// `ShardedLru`: IP-keyed (attacker-controlled) → bound HARD realtime (evict LRU O(1)).
    /// Pre-fix: DashMap con cap soft enforced solo nello sweep periodico.
    ips: ShardedLru<IpAddr, IpRecord>,
    sweep_counter: std::sync::atomic::AtomicU64,
}

impl Default for SlowEnumerationDetector {
    fn default() -> Self { Self::new() }
}

impl SlowEnumerationDetector {
    pub fn new() -> Self {
        Self { ips: ShardedLru::new(MAX_TRACKED_IPS), sweep_counter: std::sync::atomic::AtomicU64::new(0) }
    }

    /// Registra una risposta osservata (production: clock reale). Vedi `record_at` per i test.
    pub fn record(&self, ip: IpAddr, status: u16, path: &str) -> Option<EnumCandidate> {
        self.record_at(ip, status, path, Instant::now())
    }

    /// Registra una risposta osservata con clock iniettato. Conta SOLO gli status di probing
    /// (401/403/404); gli altri sono ignorati (nessuno stato, nessun candidate). Ritorna
    /// `Some` se l'IP ha ≥ MIN_DISTINCT_PATHS path DISTINTI nella finestra. NON banna, no I/O.
    pub fn record_at(&self, ip: IpAddr, status: u16, path: &str, now: Instant) -> Option<EnumCandidate> {
        if !is_probe_status(status) {
            return None; // 200 (navigazione)/302/5xx → non è probing di struttura/accesso
        }
        self.maybe_sweep(now);

        let normalized = normalize_path(path);
        // Tutto sotto UN solo borrow mut del record: registra, conta i distinti, e applica
        // il cooldown (1 candidate per IP per REPORT_COOLDOWN) — anti-spam di threat-record.
        // Tutto sotto UN solo lock dello shard (with_entry_mut). Gli early-exit del blocco
        // diventano `None` ritornato dalla closure → la funzione esterna ritorna None.
        let distinct = self.ips.with_entry_mut(ip, || IpRecord::new(now), |rec| {
            rec.record(normalized, now);
            let distinct = rec.distinct_in_window(WINDOW, now);
            if distinct.len() < MIN_DISTINCT_PATHS {
                return None;
            }
            let cooldown_active = rec
                .last_reported
                .is_some_and(|t| now.duration_since(t) < REPORT_COOLDOWN);
            if cooldown_active {
                return None; // già segnalato di recente → niente threat-record duplicato
            }
            rec.last_reported = Some(now);
            Some(distinct)
        });
        let distinct = match distinct {
            Some(d) => d,
            None => return None,
        };

        let mut sample = distinct;
        let distinct_count = sample.len();
        sample.truncate(EVIDENCE_PATH_CAP);
        Some(EnumCandidate {
            distinct_count,
            sample_paths: sample,
            window_secs: WINDOW.as_secs(),
        })
    }

    /// RECLAIM periodico degli IP idle (libera RAM). Il bound della mappa NON dipende più
    /// da qui: è strutturale in `ShardedLru` (evict LRU O(1) al superamento di
    /// MAX_TRACKED_IPS). Niente più `clear()` di degradazione (era la rete del cap soft).
    fn maybe_sweep(&self, now: Instant) {
        use std::sync::atomic::Ordering;
        let n = self.sweep_counter.fetch_add(1, Ordering::Relaxed);
        if !n.is_multiple_of(SWEEP_EVERY) {
            return;
        }
        self.ips.retain(|_, rec| now.duration_since(rec.last_activity) < IDLE_TIMEOUT);
    }

    #[cfg(test)]
    fn tracked_ips(&self) -> usize { self.ips.len() }
}

// ─── Test (bug-bounty + anti-regressione, clock iniettato → deterministici) ──────
#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr { IpAddr::from([10, 0, 0, n]) }
    fn t0() -> Instant { Instant::now() }

    /// Alimenta N path con lo stesso status; ritorna il PRIMO candidate emesso (quando
    /// scatta la soglia). Col cooldown gli hit successivi sono soppressi → "ultimo" sarebbe
    /// None, "primo" è il momento dello scatto.
    fn feed(d: &SlowEnumerationDetector, ip: IpAddr, status: u16, paths: &[&str], now: Instant) -> Option<EnumCandidate> {
        for p in paths {
            if let Some(c) = d.record_at(ip, status, p, now) { return Some(c); }
        }
        None
    }

    #[test]
    fn ten_distinct_404_in_window_triggers_candidate() {
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let paths: Vec<String> = (0..10).map(|i| format!("/probe/{i}")).collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let c = feed(&d, ip(1), 404, &refs, now).expect("10 distinti → candidate");
        assert_eq!(c.distinct_count, 10);
        assert_eq!(c.window_secs, 15 * 60);
        assert_eq!(c.sample_paths.len(), 10);
    }

    #[test]
    fn nine_distinct_does_not_trigger() {
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let paths: Vec<String> = (0..9).map(|i| format!("/probe/{i}")).collect();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        assert!(feed(&d, ip(1), 404, &refs, now).is_none(), "9 distinti → niente");
    }

    #[test]
    fn status_401_403_404_all_count_as_probing() {
        // I tre status di probing si SOMMANO sullo stesso IP (mappa struttura + accessi).
        let d = SlowEnumerationDetector::new();
        let now = t0();
        for i in 0..4 { d.record_at(ip(1), 404, &format!("/missing/{i}"), now); }
        for i in 0..3 { d.record_at(ip(1), 403, &format!("/forbidden/{i}"), now); }
        let mut last = None;
        for i in 0..3 { last = d.record_at(ip(1), 401, &format!("/protected/{i}"), now); }
        let c = last.expect("4×404 + 3×403 + 3×401 = 10 distinti → candidate");
        assert_eq!(c.distinct_count, 10);
    }

    #[test]
    fn status_200_302_5xx_are_ignored_no_false_positive() {
        // 🚨 ANTI-FALSO-POSITIVO: navigazione (200), redirect (302) e errori server (5xx)
        // NON sono probing → non contano, mai candidate per quanto numerosi.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        for status in [200u16, 302, 500, 503] {
            let paths: Vec<String> = (0..15).map(|i| format!("/page/{status}/{i}")).collect();
            let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
            assert!(feed(&d, ip(1), status, &refs, now).is_none(), "status {status} non è probing");
        }
        assert_eq!(d.tracked_ips(), 0, "nessuno stato registrato per status non-probing");
    }

    #[test]
    fn mixed_probe_and_benign_only_counts_probe() {
        // 9 path 404 (probing) + 50 path 200 (navigazione) → solo i 9 contano → niente.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        for i in 0..50 { d.record_at(ip(1), 200, &format!("/real/{i}"), now); }
        for i in 0..9 { d.record_at(ip(1), 404, &format!("/probe/{i}"), now); }
        let hits = d.ips.with_peek(&ip(1), |o| o.expect("record presente").hits.len());
        assert_eq!(hits, 9, "solo i 9 probe registrati, i 200 ignorati");
    }

    #[test]
    fn same_path_repeated_is_one_distinct_no_false_positive() {
        // Un utente che ricarica/ritenta lo STESSO 404 20 volte NON è enumeration.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let refs = vec!["/missing"; 20];
        assert!(feed(&d, ip(1), 404, &refs, now).is_none());
    }

    #[test]
    fn query_string_case_and_trailing_slash_collapse_to_one() {
        // /X?a=1, /x/, /x → STESSO path → 1 distinto (no inflation del conteggio).
        let d = SlowEnumerationDetector::new();
        let now = t0();
        assert!(feed(&d, ip(1), 404, &["/X?a=1", "/x/", "/x", "/x?b=2"], now).is_none());
    }

    #[test]
    fn old_hits_outside_window_dont_count() {
        // 9 path "vecchi" (oltre 15 min) + 1 nuovo → solo 1 in finestra → niente candidate.
        let d = SlowEnumerationDetector::new();
        let start = t0();
        for i in 0..9 { d.record_at(ip(1), 404, &format!("/old/{i}"), start); }
        let later = start + Duration::from_secs(16 * 60);
        assert!(d.record_at(ip(1), 404, "/new", later).is_none(), "i vecchi sono scaduti");
    }

    #[test]
    fn window_boundary_keeps_recent_only() {
        // 5 path a t, 5 path a t+14min → tutti entro 15min dall'ultimo → 10 → candidate.
        let d = SlowEnumerationDetector::new();
        let start = t0();
        for i in 0..5 { d.record_at(ip(1), 404, &format!("/a/{i}"), start); }
        let mid = start + Duration::from_secs(14 * 60);
        let mut last = None;
        for i in 0..5 { last = d.record_at(ip(1), 404, &format!("/b/{i}"), mid); }
        assert!(last.is_some(), "10 distinti entro 15min → candidate");
    }

    #[test]
    fn distinct_ips_are_isolated() {
        // IP-A 10 distinti → candidate; IP-B 5 distinti → niente. Nessuna contaminazione.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let a: Vec<String> = (0..10).map(|i| format!("/a/{i}")).collect();
        let ar: Vec<&str> = a.iter().map(String::as_str).collect();
        assert!(feed(&d, ip(1), 404, &ar, now).is_some());
        assert!(feed(&d, ip(2), 404, &["/b/1", "/b/2", "/b/3", "/b/4", "/b/5"], now).is_none());
    }

    #[test]
    fn per_ip_paths_are_bounded() {
        // Oltre MAX_PATHS_PER_IP il record non cresce illimitato (anti-OOM).
        let d = SlowEnumerationDetector::new();
        let now = t0();
        for i in 0..(MAX_PATHS_PER_IP + 200) {
            d.record_at(ip(1), 404, &format!("/x/{i}"), now);
        }
        let hits = d.ips.with_peek(&ip(1), |o| o.expect("record presente").hits.len());
        assert!(hits <= MAX_PATHS_PER_IP, "hits bounded");
    }

    /// 🚨 SESSION1/OOM: la mappa `ips` (IP-keyed) è bounded in TEMPO REALE via ShardedLru
    /// (evict LRU O(1)), non solo via lo sweep periodico (che faceva retain idle + clear).
    /// Mutation-verify: senza il cap ShardedLru → tracked_ips() == 5000 invece di == cap.
    #[test]
    fn ips_map_bounded_realtime_under_ip_flood() {
        let d = SlowEnumerationDetector {
            ips: ShardedLru::new(64), // multiplo dei 16 shard → capacity()==64
            sweep_counter: std::sync::atomic::AtomicU64::new(0),
        };
        let now = t0();
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let addr = IpAddr::from([10, 0, b[2], b[3]]); // 5000 IP distinti
            d.record_at(addr, 404, "/x", now);
        }
        assert_eq!(d.tracked_ips(), 64, "ips non bounded realtime (got {})", d.tracked_ips());
    }

    #[test]
    fn idle_ips_are_evicted_on_sweep() {
        let d = SlowEnumerationDetector::new();
        let start = t0();
        d.record_at(ip(1), 404, "/x", start);
        assert_eq!(d.tracked_ips(), 1);
        let later = start + Duration::from_secs(31 * 60);
        for _ in 0..SWEEP_EVERY { d.record_at(ip(2), 404, "/y", later); }
        assert!(!d.ips.contains(&ip(1)), "IP idle evicted");
    }

    #[test]
    fn cooldown_emits_one_candidate_per_window_not_per_hit() {
        // 🚨 ANTI-SPAM: un IP che fa 30 path-404 in burst genera UN SOLO candidate
        // (al 10°), non ~21 threat-record duplicati. Il cooldown sopprime i successivi.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let mut candidates = 0;
        for i in 0..30 {
            if d.record_at(ip(1), 404, &format!("/p/{i}"), now).is_some() { candidates += 1; }
        }
        assert_eq!(candidates, 1, "un solo candidate per finestra (anti-spam)");
    }

    #[test]
    fn reemits_after_cooldown_with_fresh_paths() {
        // Dopo il cooldown, un IP ancora ostile (10 path NUOVI) ri-emette un candidate.
        let d = SlowEnumerationDetector::new();
        let start = t0();
        for i in 0..10 { d.record_at(ip(1), 404, &format!("/old/{i}"), start); } // candidate #1
        // Oltre cooldown E oltre finestra → i vecchi scadono, 10 nuovi → candidate #2.
        let later = start + Duration::from_secs(16 * 60);
        let fresh: Vec<String> = (0..10).map(|i| format!("/new/{i}")).collect();
        let refs: Vec<&str> = fresh.iter().map(String::as_str).collect();
        assert!(feed(&d, ip(1), 404, &refs, later).is_some(), "ri-emette dopo il cooldown");
    }

    #[test]
    fn candidate_evidence_never_exceeds_cap() {
        // Proprietà difensiva: sample_paths non supera mai EVIDENCE_PATH_CAP.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let c = (0..30)
            .filter_map(|i| d.record_at(ip(1), 404, &format!("/p/{i}"), now))
            .next()
            .unwrap();
        assert!(c.sample_paths.len() <= EVIDENCE_PATH_CAP);
        assert_eq!(c.distinct_count, c.sample_paths.len().min(c.distinct_count));
    }

    #[test]
    fn real_world_scanner_mapping_structure() {
        // Profilo reale: un IP che mappa la struttura con 404/403 su endpoint plausibili
        // (NON esche honeypot) → candidate. È il caso che honeypot/Rule-1 mancano.
        let d = SlowEnumerationDetector::new();
        let now = t0();
        let scan = [
            "/api/v1/users", "/api/v1/admin", "/api/internal/config", "/dashboard",
            "/v2/api/users", "/backup-old", "/api/v2/secrets", "/management/health",
            "/private/api", "/legacy/login", "/api/v1/tokens",
        ];
        assert!(feed(&d, ip(7), 404, &scan, now).is_some(), "scan struttura reale → candidate");
    }
}
