//! Intent Detection (Section C2 -- Sentinel WAF v2.0.0)
//!
//! Analyzes per-IP path sequences to recognize attack intents:
//!
//! - **Reconnaissance**: 3+ sensitive paths (/login, /admin, /config, ...) in 60s
//! - **CredentialStuffing**: 3+ POST to /login or /auth in 30s
//! - **DataExfiltration**: 5+ GET on same resource with incremental IDs in 60s
//! - **VulnerabilityProbe**: 3+ honeypot/scanner paths in 120s
//! - **ApiEnumeration**: 10+ unique /api/* paths in 30s
//! - **ContentScraping**: 20+ GET on same collection with sequential IDs in 120s
//!
//! Chain bonus: 2+ different intents in the same 10min session escalate risk
//! (e.g. Recon + VulnProbe + DataExfil = kill chain, +0.6).
//!
//! Bounded: max 50 events per IP session, 10000 total sessions, LRU eviction,
//! 10min idle expiry.

use sentinel_core::sharded_lru::ShardedLru;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum path events stored per IP session
const MAX_EVENTS_PER_SESSION: usize = 50;
/// Events to retain when compacting (keep last N + intent-triggering events)
const COMPACT_KEEP_RECENT: usize = 25;
/// Maximum total sessions tracked
const MAX_TOTAL_SESSIONS: usize = 10_000;
/// Session idle timeout (10 minutes)
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Chain bonus window (10 minutes)
const CHAIN_BONUS_WINDOW: Duration = Duration::from_secs(600);

// ─── Intent thresholds ───────────────────────────────────────────────────────

const RECON_MIN_PATHS: usize = 3;
const RECON_WINDOW: Duration = Duration::from_secs(60);
const RECON_RISK_ADD: f64 = 0.5;

const CRED_STUFF_MIN_POSTS: usize = 3;
const CRED_STUFF_WINDOW: Duration = Duration::from_secs(30);
const CRED_STUFF_RISK_ADD: f64 = 0.6;

const DATA_EXFIL_MIN_GETS: usize = 5;
const DATA_EXFIL_WINDOW: Duration = Duration::from_secs(60);
const DATA_EXFIL_RISK_ADD: f64 = 0.4;

const VULN_PROBE_MIN_PATHS: usize = 3;
const VULN_PROBE_WINDOW: Duration = Duration::from_secs(120);
const VULN_PROBE_RISK_ADD: f64 = 0.7;

const API_ENUM_MIN_UNIQUE: usize = 10;
const API_ENUM_WINDOW: Duration = Duration::from_secs(30);
const API_ENUM_RISK_ADD: f64 = 0.5;

const CONTENT_SCRAPE_MIN_GETS: usize = 20;
const CONTENT_SCRAPE_WINDOW: Duration = Duration::from_secs(120);
const CONTENT_SCRAPE_RISK_ADD: f64 = 0.3;

// ─── Sensitive paths (Reconnaissance) ────────────────────────────────────────

const SENSITIVE_PATHS: &[&str] = &[
    "/login",
    "/admin",
    "/config",
    "/api-docs",
    "/.env",
    "/swagger",
    "/graphql",
    "/api/auth",
    "/api/internal",
    "/api/admin",
    "/settings",
    "/console",
    "/debug",
];

// ─── Honeypot/Scanner paths (VulnerabilityProbe) ─────────────────────────────

const HONEYPOT_PATHS: &[&str] = &[
    "/wp-admin",
    "/.env",
    "/phpmyadmin",
    "/actuator",
    "/.git",
    "/backup",
    "/wp-login.php",
    "/xmlrpc.php",
    "/.git/config",
    "/.git/head",
    "/pma",
    "/adminer",
    "/actuator/health",
    "/actuator/env",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/cgi-bin/",
    "/solr",
    "/elasticsearch",
    "/_cat",
    "/shell",
    "/cmd",
];

// ─── Types ───────────────────────────────────────────────────────────────────

/// Recognized attack intent derived from path sequence analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecognizedIntent {
    /// /login -> /admin -> /config -> /api-docs (probing sensitive endpoints)
    Reconnaissance,
    /// POST /login x3+ in 30s (brute force credentials)
    CredentialStuffing,
    /// GET /api/users/1 -> /api/users/2 -> ... (sequential data harvesting)
    DataExfiltration,
    /// /wp-admin -> /.env -> /phpmyadmin -> /actuator (scanner tooling)
    VulnerabilityProbe,
    /// /api/v1/a -> /api/v1/b -> /api/v1/c (API surface discovery)
    ApiEnumeration,
    /// GET /products/1 -> /products/2 -> ... (systematic content harvesting)
    ContentScraping,
}

/// A single detected intent with its risk contribution
#[derive(Debug, Clone)]
pub struct IntentDetection {
    /// The recognized attack intent
    pub intent: RecognizedIntent,
    /// Risk score addition (0.0 - 1.0)
    pub risk_add: f64,
    /// Number of matching paths that triggered this detection
    pub matched_paths: usize,
}

/// Result of intent analysis for a single request
#[derive(Debug, Clone)]
pub struct IntentAnalysisResult {
    /// All intents detected in this analysis pass
    pub intents: Vec<IntentDetection>,
    /// Bonus risk for 2+ different intents in the same session (kill chain)
    pub chain_bonus: f64,
}

// ─── Session internals ───────────────────────────────────────────────────────

/// A single path event in the session
#[derive(Debug, Clone)]
struct PathEvent {
    /// Normalized path (lowercase, query stripped)
    path: String,
    /// HTTP method (uppercase)
    method: String,
    /// Timestamp of the request
    timestamp: Instant,
    /// Whether this event contributed to an intent detection
    triggered_intent: bool,
}

/// Per-IP session record tracking path sequences
struct SessionRecord {
    /// Path event history (bounded circular buffer)
    events: VecDeque<PathEvent>,
    /// Set of distinct intents detected during this session's lifetime
    detected_intents: HashSet<RecognizedIntent>,
    /// Latest detection timestamp PER intent type (per la finestra del chain bonus).
    /// `HashMap` (non `Vec`) → bounded a ≤ N varianti di `RecognizedIntent`: il reader
    /// (`calculate_chain_bonus`) considera solo se un tipo ha un timestamp nella finestra,
    /// quindi tenere l'ULTIMO per tipo è equivalente. Anti-OOM: un `Vec` cresceva di una
    /// entry a OGNI detection → un attaccante che ritriggera intent lo gonfiava illimitato.
    intent_timestamps: HashMap<RecognizedIntent, Instant>,
    /// Last activity timestamp (for idle eviction)
    last_activity: Instant,
}

impl SessionRecord {
    fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS_PER_SESSION),
            detected_intents: HashSet::new(),
            intent_timestamps: HashMap::new(),
            last_activity: Instant::now(),
        }
    }

    /// Record a new path event, compacting if necessary
    fn record(&mut self, path: &str, method: &str) {
        let now = Instant::now();
        self.last_activity = now;

        // Compact if at capacity
        if self.events.len() >= MAX_EVENTS_PER_SESSION {
            self.compact();
        }

        self.events.push_back(PathEvent {
            path: normalize_intent_path(path),
            method: method.to_uppercase(),
            timestamp: now,
            triggered_intent: false,
        });
    }

    /// Compact the event buffer: keep last COMPACT_KEEP_RECENT + all intent-triggering events.
    /// Hard cap MAX_EVENTS_PER_SESSION — se anche dopo il partition si supera,
    /// scarta i piu\` vecchi mantenendo quelli con triggered_intent finche\` possibile.
    fn compact(&mut self) {
        let len = self.events.len();
        if len <= COMPACT_KEEP_RECENT {
            return;
        }

        // Partition: events that triggered intents vs those that didn't
        let cutoff = len.saturating_sub(COMPACT_KEEP_RECENT);
        let mut retained = VecDeque::with_capacity(MAX_EVENTS_PER_SESSION);

        for (i, event) in self.events.iter().enumerate() {
            if event.triggered_intent || i >= cutoff {
                retained.push_back(event.clone());
            }
        }

        // Hard cap: se retained >= MAX, droppa i piu\` vecchi (front).
        // NB: cap a MAX-1 perche\` record() pusha SUBITO dopo compact() un nuovo
        // evento → l'evento finale arriverebbe a MAX+1 senza questo margine.
        while retained.len() >= MAX_EVENTS_PER_SESSION {
            retained.pop_front();
        }

        self.events = retained;
    }

    /// Check if this session has been idle beyond the timeout
    fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > SESSION_IDLE_TIMEOUT
    }

    /// Get events within a time window from now
    fn events_in_window(&self, window: Duration) -> impl Iterator<Item = &PathEvent> {
        let cutoff = Instant::now() - window;
        self.events.iter().filter(move |e| e.timestamp >= cutoff)
    }
}

// ─── IntentDetector ──────────────────────────────────────────────────────────

/// Intent detector: analyzes per-IP path sequences to recognize attack intents
pub struct IntentDetector {
    /// Per-IP session tracking. `ShardedLru` → bound HARD della memoria in TEMPO REALE:
    /// quando lo shard è pieno l'inserimento di un IP nuovo evicta la LRU in O(1). Pre-fix
    /// (DashMap): il cap MAX_TOTAL_SESSIONS era enforced SOLO nella cleanup periodica →
    /// fra una cleanup e l'altra un flood di IP distinti cresceva illimitato = OOM.
    sessions: ShardedLru<IpAddr, SessionRecord>,
}

impl IntentDetector {
    /// Create a new intent detector
    pub fn new() -> Self {
        Self {
            sessions: ShardedLru::new(MAX_TOTAL_SESSIONS),
        }
    }

    /// Builder (test/tuning): override della capacity HARD della LRU sessioni (anti-OOM).
    pub fn with_max_sessions(max: usize) -> Self {
        Self {
            sessions: ShardedLru::new(max.max(1)),
        }
    }

    /// Record a path event and analyze the session for attack intents.
    ///
    /// Returns all detected intents and any chain bonus.
    pub fn analyze(&self, ip: IpAddr, path: &str, method: &str) -> IntentAnalysisResult {
        // `with_entry_mut`: get-or-create la sessione per-IP + evict LRU O(1) se lo shard
        // è pieno (bound HARD realtime). L'analisi gira tutta sotto il lock dello shard;
        // i `check_*` leggono solo la sessione passata (non toccano `self.sessions`) →
        // nessuna ri-entranza sul lock.
        self.sessions
            .with_entry_mut(ip, SessionRecord::new, |session| {
                self.analyze_session(session, path, method)
            })
    }

    /// Corpo dell'analisi su una sessione già recuperata/creata (sotto lock shard).
    fn analyze_session(
        &self,
        session: &mut SessionRecord,
        path: &str,
        method: &str,
    ) -> IntentAnalysisResult {
        // Record the event
        session.record(path, method);

        // Run all intent pattern checks
        let mut intents = Vec::new();

        if let Some(detection) = self.check_reconnaissance(&*session) {
            session.detected_intents.insert(RecognizedIntent::Reconnaissance);
            session.intent_timestamps.insert(RecognizedIntent::Reconnaissance, Instant::now());
            intents.push(detection);
        }

        if let Some(detection) = self.check_credential_stuffing(&*session) {
            session.detected_intents.insert(RecognizedIntent::CredentialStuffing);
            session.intent_timestamps.insert(RecognizedIntent::CredentialStuffing, Instant::now());
            intents.push(detection);
        }

        if let Some(detection) = self.check_data_exfiltration(&*session) {
            session.detected_intents.insert(RecognizedIntent::DataExfiltration);
            session.intent_timestamps.insert(RecognizedIntent::DataExfiltration, Instant::now());
            intents.push(detection);
        }

        if let Some(detection) = self.check_vulnerability_probe(&*session) {
            session.detected_intents.insert(RecognizedIntent::VulnerabilityProbe);
            session.intent_timestamps.insert(RecognizedIntent::VulnerabilityProbe, Instant::now());
            intents.push(detection);
        }

        if let Some(detection) = self.check_api_enumeration(&*session) {
            session.detected_intents.insert(RecognizedIntent::ApiEnumeration);
            session.intent_timestamps.insert(RecognizedIntent::ApiEnumeration, Instant::now());
            intents.push(detection);
        }

        if let Some(detection) = self.check_content_scraping(&*session) {
            session.detected_intents.insert(RecognizedIntent::ContentScraping);
            session.intent_timestamps.insert(RecognizedIntent::ContentScraping, Instant::now());
            intents.push(detection);
        }

        // Mark triggering events
        for detection in &intents {
            Self::mark_triggering_events(session, detection);
        }

        // Calculate chain bonus
        let chain_bonus = self.calculate_chain_bonus(&*session);

        IntentAnalysisResult {
            intents,
            chain_bonus,
        }
    }

    // ─── Intent pattern checks ───────────────────────────────────────────

    /// Reconnaissance: 3+ sensitive paths in 60s
    fn check_reconnaissance(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let sensitive_count: usize = session
            .events_in_window(RECON_WINDOW)
            .filter(|e| is_sensitive_path(&e.path))
            .collect::<HashSet<_>>()
            .len();

        // Count unique sensitive paths, not just hits
        let unique_sensitive: HashSet<&str> = session
            .events_in_window(RECON_WINDOW)
            .filter(|e| is_sensitive_path(&e.path))
            .map(|e| e.path.as_str())
            .collect();

        if unique_sensitive.len() >= RECON_MIN_PATHS {
            Some(IntentDetection {
                intent: RecognizedIntent::Reconnaissance,
                risk_add: RECON_RISK_ADD,
                matched_paths: unique_sensitive.len(),
            })
        } else {
            let _ = sensitive_count; // suppress warning
            None
        }
    }

    /// Credential stuffing: 3+ POST to /login or /auth in 30s
    fn check_credential_stuffing(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let auth_posts: usize = session
            .events_in_window(CRED_STUFF_WINDOW)
            .filter(|e| {
                e.method == "POST"
                    && (e.path.contains("/login")
                        || e.path.contains("/auth")
                        || e.path.contains("/signin")
                        || e.path.contains("/authenticate"))
            })
            .count();

        if auth_posts >= CRED_STUFF_MIN_POSTS {
            Some(IntentDetection {
                intent: RecognizedIntent::CredentialStuffing,
                risk_add: CRED_STUFF_RISK_ADD,
                matched_paths: auth_posts,
            })
        } else {
            None
        }
    }

    /// Data exfiltration: 5+ GET on same resource with incremental IDs in 60s
    fn check_data_exfiltration(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let get_events: Vec<&PathEvent> = session
            .events_in_window(DATA_EXFIL_WINDOW)
            .filter(|e| e.method == "GET")
            .collect();

        if get_events.len() < DATA_EXFIL_MIN_GETS {
            return None;
        }

        // Group by base path (path without the last numeric segment)
        let mut base_path_counts: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();

        for event in &get_events {
            if let Some((base, id)) = extract_base_and_id(&event.path) {
                base_path_counts.entry(base).or_default().push(id);
            }
        }

        // Check for sequential/incremental IDs on any base path
        for (_, ids) in &base_path_counts {
            if ids.len() >= DATA_EXFIL_MIN_GETS && has_sequential_ids(ids) {
                return Some(IntentDetection {
                    intent: RecognizedIntent::DataExfiltration,
                    risk_add: DATA_EXFIL_RISK_ADD,
                    matched_paths: ids.len(),
                });
            }
        }

        None
    }

    /// Vulnerability probe: 3+ honeypot/scanner paths in 120s
    fn check_vulnerability_probe(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let unique_honeypot: HashSet<&str> = session
            .events_in_window(VULN_PROBE_WINDOW)
            .filter(|e| is_honeypot_path(&e.path))
            .map(|e| e.path.as_str())
            .collect();

        if unique_honeypot.len() >= VULN_PROBE_MIN_PATHS {
            Some(IntentDetection {
                intent: RecognizedIntent::VulnerabilityProbe,
                risk_add: VULN_PROBE_RISK_ADD,
                matched_paths: unique_honeypot.len(),
            })
        } else {
            None
        }
    }

    /// API enumeration: 10+ unique /api/* paths in 30s
    fn check_api_enumeration(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let unique_api_paths: HashSet<&str> = session
            .events_in_window(API_ENUM_WINDOW)
            .filter(|e| e.path.starts_with("/api/") || e.path.starts_with("/api."))
            .map(|e| e.path.as_str())
            .collect();

        if unique_api_paths.len() >= API_ENUM_MIN_UNIQUE {
            Some(IntentDetection {
                intent: RecognizedIntent::ApiEnumeration,
                risk_add: API_ENUM_RISK_ADD,
                matched_paths: unique_api_paths.len(),
            })
        } else {
            None
        }
    }

    /// Content scraping: 20+ GET on same collection with sequential IDs in 120s
    fn check_content_scraping(&self, session: &SessionRecord) -> Option<IntentDetection> {
        let get_events: Vec<&PathEvent> = session
            .events_in_window(CONTENT_SCRAPE_WINDOW)
            .filter(|e| e.method == "GET")
            .collect();

        if get_events.len() < CONTENT_SCRAPE_MIN_GETS {
            return None;
        }

        // Group by base path (collection prefix)
        let mut base_path_counts: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();

        for event in &get_events {
            if let Some((base, id)) = extract_base_and_id(&event.path) {
                base_path_counts.entry(base).or_default().push(id);
            }
        }

        // Check for sequential access patterns on any collection
        for (_, ids) in &base_path_counts {
            if ids.len() >= CONTENT_SCRAPE_MIN_GETS && has_sequential_ids(ids) {
                return Some(IntentDetection {
                    intent: RecognizedIntent::ContentScraping,
                    risk_add: CONTENT_SCRAPE_RISK_ADD,
                    matched_paths: ids.len(),
                });
            }
        }

        None
    }

    // ─── Chain bonus (C2 fix) ────────────────────────────────────────────

    /// Calculate chain bonus for multiple intents in the same 10min window.
    ///
    /// Specific combinations yield higher bonuses:
    /// - Recon + VulnProbe + DataExfil = kill chain (+0.6)
    /// - VulnProbe + DataExfil = escalating attack (+0.4)
    /// - Recon + VulnProbe = targeted scanning (+0.3)
    /// - Any other 2+ combination = generic multi-intent (+0.2)
    fn calculate_chain_bonus(&self, session: &SessionRecord) -> f64 {
        let now = Instant::now();

        // Collect unique intents within the chain bonus window
        let recent_intents: HashSet<RecognizedIntent> = session
            .intent_timestamps
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) <= CHAIN_BONUS_WINDOW)
            .map(|(intent, _)| *intent)
            .collect();

        if recent_intents.len() < 2 {
            return 0.0;
        }

        let has_recon = recent_intents.contains(&RecognizedIntent::Reconnaissance);
        let has_vuln = recent_intents.contains(&RecognizedIntent::VulnerabilityProbe);
        let has_exfil = recent_intents.contains(&RecognizedIntent::DataExfiltration);

        // Kill chain: Recon + VulnProbe + DataExfil
        if has_recon && has_vuln && has_exfil {
            return 0.6;
        }

        // Escalating attack: VulnProbe + DataExfil
        if has_vuln && has_exfil {
            return 0.4;
        }

        // Targeted scanning: Recon + VulnProbe
        if has_recon && has_vuln {
            return 0.3;
        }

        // Generic multi-intent: any other 2+ combination
        0.2
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    /// Mark events that contributed to a detection as intent-triggering
    /// (prevents them from being evicted during compaction)
    fn mark_triggering_events(session: &mut SessionRecord, _detection: &IntentDetection) {
        // Mark the most recent events matching the intent pattern
        // This ensures compaction retains them
        for event in session.events.iter_mut().rev().take(MAX_EVENTS_PER_SESSION) {
            if !event.triggered_intent {
                // Simple heuristic: mark recent events as triggering
                // A more precise approach would track which events contributed
                // to each specific detection, but this is sufficient for
                // preventing compaction loss
                event.triggered_intent = true;
                break;
            }
        }
    }

    /// Periodic RECLAIM: remove idle sessions (libera RAM degli IP fermi prima che la
    /// LRU li sfratti). Il cap totale NON è più enforced qui con un sort O(n): è
    /// strutturale in `ShardedLru` (evict LRU O(1) all'inserimento in `analyze`).
    pub fn cleanup(&self) {
        // Remove sessions idle > 10 min
        self.sessions.retain(|_, session| !session.is_idle());
    }

    /// Number of actively tracked sessions
    pub fn tracked_sessions(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for IntentDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Path utilities ──────────────────────────────────────────────────────────

/// Normalize a path for intent matching: lowercase, strip query string
fn normalize_intent_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    path.to_lowercase()
}

/// Check if a path matches any sensitive endpoint pattern
fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS
        .iter()
        .any(|&sensitive| path.starts_with(sensitive))
}

/// Check if a path matches any honeypot/scanner endpoint pattern
fn is_honeypot_path(path: &str) -> bool {
    HONEYPOT_PATHS
        .iter()
        .any(|&honeypot| path.starts_with(honeypot))
}

/// Extract the base path (without trailing numeric ID) and the ID itself.
///
/// Examples:
///   "/api/users/123"     -> Some(("/api/users", 123))
///   "/products/42"       -> Some(("/products", 42))
///   "/api/users"         -> None (no numeric suffix)
///   "/api/users/abc"     -> None (suffix not numeric)
fn extract_base_and_id(path: &str) -> Option<(String, u64)> {
    let path = path.trim_end_matches('/');
    let last_slash = path.rfind('/')?;
    // SAFE-SLICE: last_slash = rfind('/') → indice valido di '/' (ASCII) → sia last_slash
    // sia last_slash+1 sono char-boundary; len ≥ last_slash+1 → nessun panic.
    let base = &path[..last_slash];
    let suffix = &path[last_slash + 1..];

    if base.is_empty() {
        return None;
    }

    suffix.parse::<u64>().ok().map(|id| (base.to_string(), id))
}

/// Check if a sequence of IDs has a sequential/incremental pattern.
///
/// Considers IDs sequential if > 60% of consecutive pairs differ by exactly 1.
fn has_sequential_ids(ids: &[u64]) -> bool {
    if ids.len() < 2 {
        return false;
    }

    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    if sorted.len() < 2 {
        return false;
    }

    let sequential_pairs = sorted
        .windows(2)
        .filter(|w| w[1] - w[0] <= 2) // Allow small gaps (1 or 2)
        .count();

    let total_pairs = sorted.len() - 1;

    // > 60% sequential = deliberate enumeration
    (sequential_pairs as f64 / total_pairs as f64) > 0.6
}

// ─── Hashable PathEvent ref (for dedup in reconnaissance) ────────────────────

impl std::hash::Hash for PathEvent {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.method.hash(state);
    }
}

impl PartialEq for PathEvent {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.method == other.method
    }
}

impl Eq for PathEvent {}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: create IpAddr from the last octet
    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn test_reconnaissance_detection() {
        let detector = IntentDetector::new();
        let addr = ip(1);

        // Hit 4 different sensitive paths
        detector.analyze(addr, "/login", "GET");
        detector.analyze(addr, "/admin", "GET");
        detector.analyze(addr, "/config", "GET");
        let result = detector.analyze(addr, "/api-docs", "GET");

        let recon = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::Reconnaissance);
        assert!(
            recon.is_some(),
            "Expected Reconnaissance detection for 4 sensitive paths"
        );
        assert_eq!(recon.unwrap().risk_add, RECON_RISK_ADD);
        assert!(recon.unwrap().matched_paths >= RECON_MIN_PATHS);
    }

    #[test]
    fn test_credential_stuffing_detection() {
        let detector = IntentDetector::new();
        let addr = ip(2);

        // POST /login 4 times rapidly
        detector.analyze(addr, "/login", "POST");
        detector.analyze(addr, "/login", "POST");
        detector.analyze(addr, "/login", "POST");
        let result = detector.analyze(addr, "/auth/login", "POST");

        let cred = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::CredentialStuffing);
        assert!(
            cred.is_some(),
            "Expected CredentialStuffing detection for 4 POST /login"
        );
        assert_eq!(cred.unwrap().risk_add, CRED_STUFF_RISK_ADD);
        assert!(cred.unwrap().matched_paths >= CRED_STUFF_MIN_POSTS);
    }

    #[test]
    fn test_vulnerability_probe_detection() {
        let detector = IntentDetector::new();
        let addr = ip(3);

        // Hit 4 different honeypot paths
        detector.analyze(addr, "/wp-admin", "GET");
        detector.analyze(addr, "/.env", "GET");
        detector.analyze(addr, "/phpmyadmin", "GET");
        let result = detector.analyze(addr, "/actuator", "GET");

        let vuln = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::VulnerabilityProbe);
        assert!(
            vuln.is_some(),
            "Expected VulnerabilityProbe detection for 4 honeypot paths"
        );
        assert_eq!(vuln.unwrap().risk_add, VULN_PROBE_RISK_ADD);
        assert!(vuln.unwrap().matched_paths >= VULN_PROBE_MIN_PATHS);
    }

    #[test]
    fn test_api_enumeration_detection() {
        let detector = IntentDetector::new();
        let addr = ip(4);

        // Hit 11 unique API paths rapidly
        for i in 0..11 {
            detector.analyze(addr, &format!("/api/v1/endpoint{}", i), "GET");
        }

        let result = detector.analyze(addr, "/api/v1/extra", "GET");

        let api_enum = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::ApiEnumeration);
        assert!(
            api_enum.is_some(),
            "Expected ApiEnumeration detection for 12 unique API paths"
        );
        assert_eq!(api_enum.unwrap().risk_add, API_ENUM_RISK_ADD);
        assert!(api_enum.unwrap().matched_paths >= API_ENUM_MIN_UNIQUE);
    }

    #[test]
    fn test_no_false_positive_for_few_paths() {
        let detector = IntentDetector::new();
        let addr = ip(5);

        // Normal browsing: just 2 paths (below all thresholds)
        detector.analyze(addr, "/", "GET");
        let result = detector.analyze(addr, "/about", "GET");

        assert!(
            result.intents.is_empty(),
            "Should NOT detect any intent for normal 2-path browsing, got: {:?}",
            result.intents
        );
        assert_eq!(result.chain_bonus, 0.0);
    }

    #[test]
    fn test_chain_bonus_two_intents() {
        let detector = IntentDetector::new();
        let addr = ip(6);

        // Trigger Reconnaissance: 3 sensitive paths
        detector.analyze(addr, "/login", "GET");
        detector.analyze(addr, "/admin", "GET");
        detector.analyze(addr, "/config", "GET");

        // Trigger VulnerabilityProbe: 3 honeypot paths
        detector.analyze(addr, "/wp-admin", "GET");
        detector.analyze(addr, "/phpmyadmin", "GET");
        let result = detector.analyze(addr, "/actuator", "GET");

        // Should have chain bonus for Recon + VulnProbe = +0.3
        assert!(
            result.chain_bonus > 0.0,
            "Expected chain bonus for 2 intents (Recon + VulnProbe)"
        );
        assert_eq!(
            result.chain_bonus, 0.3,
            "Recon + VulnProbe should yield chain bonus of 0.3"
        );
    }

    #[test]
    fn test_chain_bonus_kill_chain() {
        let detector = IntentDetector::new();
        let addr = ip(7);

        // Trigger Reconnaissance: 3 sensitive paths
        detector.analyze(addr, "/login", "GET");
        detector.analyze(addr, "/admin", "GET");
        detector.analyze(addr, "/config", "GET");

        // Trigger VulnerabilityProbe: 3 honeypot paths
        detector.analyze(addr, "/wp-admin", "GET");
        detector.analyze(addr, "/.git", "GET");
        detector.analyze(addr, "/backup", "GET");

        // Trigger DataExfiltration: 5+ sequential GET on same resource
        detector.analyze(addr, "/api/users/1", "GET");
        detector.analyze(addr, "/api/users/2", "GET");
        detector.analyze(addr, "/api/users/3", "GET");
        detector.analyze(addr, "/api/users/4", "GET");
        let result = detector.analyze(addr, "/api/users/5", "GET");

        // Verify DataExfiltration was detected
        let data_exfil = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::DataExfiltration);
        assert!(
            data_exfil.is_some(),
            "Expected DataExfiltration detection for sequential IDs"
        );

        // Kill chain: Recon + VulnProbe + DataExfil = +0.6
        assert_eq!(
            result.chain_bonus, 0.6,
            "Kill chain (Recon + VulnProbe + DataExfil) should yield chain bonus of 0.6"
        );
    }

    #[test]
    fn test_sequence_cap_enforcement() {
        let detector = IntentDetector::new();
        let addr = ip(8);

        // Record 60 events (beyond the 50-event cap)
        for i in 0..60 {
            detector.analyze(addr, &format!("/page/{}", i), "GET");
        }

        // The session should have been compacted
        let events_len = detector
            .sessions
            .with_peek(&addr, |s| s.expect("session present").events.len());
        assert!(
            events_len <= MAX_EVENTS_PER_SESSION,
            "Session should be capped at {} events, got {}",
            MAX_EVENTS_PER_SESSION,
            events_len
        );
    }

    /// 🚨 OOM: la mappa sessioni è bounded in TEMPO REALE sotto IP-rotation (`ShardedLru`
    /// evict-LRU O(1) all'inserimento in `analyze`), NON solo via la cleanup periodica.
    /// Pre-fix: il cap MAX_TOTAL_SESSIONS era enforced SOLO in cleanup() → fra una cleanup
    /// e l'altra un flood di IP distinti cresceva illimitato = OOM.
    #[test]
    fn sessions_bounded_realtime_under_ip_rotation() {
        use std::net::Ipv6Addr;
        // cap multiplo dei 16 shard → capacity()==cap; 5000 IP distinti saturano ogni shard.
        let cap = 64;
        let detector = IntentDetector::with_max_sessions(cap);
        for i in 0..5000u16 {
            let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
            detector.analyze(addr, "/x", "GET");
        }
        // == cap (non solo <=): uccide SIA "unbounded" (>cap) SIA la false-green
        // "non-inserisce-mai" (tracked_sessions()==0 <= cap passerebbe). cleanup() mai
        // chiamata → il bound è puramente strutturale.
        assert_eq!(
            detector.tracked_sessions(),
            cap,
            "OOM: sessioni devono essere bounded realtime ED esattamente piene a cap={cap} (got {})",
            detector.tracked_sessions()
        );
    }

    /// 🚨 OOM: `intent_timestamps` è bounded al NUMERO di tipi di intent (HashMap
    /// latest-per-type), non al numero di DETECTION. Pre-fix era un `Vec` con una `push`
    /// a ogni detection → un attaccante che ritriggera intent lo gonfiava illimitato.
    /// Mutation-verify: tornando a `Vec::push` → la len cresce con le 6000 analyze.
    #[test]
    fn intent_timestamps_bounded_by_type_not_detection_count() {
        let detector = IntentDetector::new();
        let addr = ip(7);
        // Ritriggera recon (3+ path sensibili) molte volte: tante detection, ma il
        // HashMap tiene solo l'ultimo timestamp per tipo.
        for _ in 0..2000 {
            detector.analyze(addr, "/.env", "GET");
            detector.analyze(addr, "/.git/config", "GET");
            detector.analyze(addr, "/wp-admin", "GET");
        }
        let n = detector
            .sessions
            .with_peek(&addr, |s| s.map_or(0, |s| s.intent_timestamps.len()));
        // Almeno un intent deve essere scattato (n>=1) E bounded ai tipi (<= 8 di margine
        // sulle varianti di RecognizedIntent). Col vecchio Vec n sarebbe migliaia.
        assert!(
            (1..=8).contains(&n),
            "intent_timestamps non bounded per-tipo (got {n})"
        );
    }

    #[test]
    fn test_cleanup_idle_sessions() {
        let detector = IntentDetector::new();
        let addr = ip(9);

        // Record some events
        detector.analyze(addr, "/page/1", "GET");
        detector.analyze(addr, "/page/2", "GET");

        assert_eq!(detector.tracked_sessions(), 1);

        // Manually set the session to be idle (simulate time passing)
        detector.sessions.with_get_mut(&addr, |s| {
            s.expect("session present").last_activity =
                Instant::now() - SESSION_IDLE_TIMEOUT - Duration::from_secs(1);
        });

        // Cleanup should remove the idle session
        detector.cleanup();
        assert_eq!(
            detector.tracked_sessions(),
            0,
            "Idle session should have been cleaned up"
        );
    }

    #[test]
    fn test_data_exfiltration_detection() {
        let detector = IntentDetector::new();
        let addr = ip(10);

        // Sequential GET on /api/users with incremental IDs
        for i in 1..=6 {
            detector.analyze(addr, &format!("/api/users/{}", i), "GET");
        }

        let result = detector.analyze(addr, "/api/users/7", "GET");

        let exfil = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::DataExfiltration);
        assert!(
            exfil.is_some(),
            "Expected DataExfiltration for 7 sequential GET /api/users/:id"
        );
        assert_eq!(exfil.unwrap().risk_add, DATA_EXFIL_RISK_ADD);
    }

    #[test]
    fn test_content_scraping_detection() {
        let detector = IntentDetector::new();
        let addr = ip(11);

        // 22 sequential GET on /products/:id
        for i in 1..=22 {
            detector.analyze(addr, &format!("/products/{}", i), "GET");
        }

        let result = detector.analyze(addr, "/products/23", "GET");

        let scrape = result
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::ContentScraping);
        assert!(
            scrape.is_some(),
            "Expected ContentScraping for 23 sequential GET /products/:id"
        );
        assert_eq!(scrape.unwrap().risk_add, CONTENT_SCRAPE_RISK_ADD);
    }

    // ─── Path utility tests ─────────────────────────────────────────────

    #[test]
    fn test_normalize_intent_path() {
        assert_eq!(normalize_intent_path("/API/Users?page=1"), "/api/users");
        assert_eq!(normalize_intent_path("/Admin"), "/admin");
        assert_eq!(normalize_intent_path("/.env"), "/.env");
    }

    #[test]
    fn test_extract_base_and_id() {
        assert_eq!(
            extract_base_and_id("/api/users/123"),
            Some(("/api/users".to_string(), 123))
        );
        assert_eq!(
            extract_base_and_id("/products/42"),
            Some(("/products".to_string(), 42))
        );
        assert_eq!(extract_base_and_id("/api/users"), None);
        assert_eq!(extract_base_and_id("/api/users/abc"), None);
        assert_eq!(extract_base_and_id("/"), None);
    }

    #[test]
    fn test_has_sequential_ids() {
        assert!(has_sequential_ids(&[1, 2, 3, 4, 5]));
        assert!(has_sequential_ids(&[5, 3, 1, 2, 4])); // Sorted internally
        assert!(has_sequential_ids(&[1, 2, 3, 5, 6])); // Small gap OK (>60% sequential)
        assert!(!has_sequential_ids(&[1, 100, 200, 300, 400])); // Random IDs
        assert!(!has_sequential_ids(&[1])); // Too few
        assert!(!has_sequential_ids(&[])); // Empty
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("/login"));
        assert!(is_sensitive_path("/admin/users"));
        assert!(is_sensitive_path("/config"));
        assert!(is_sensitive_path("/api-docs"));
        assert!(is_sensitive_path("/.env"));
        assert!(is_sensitive_path("/swagger"));
        assert!(is_sensitive_path("/graphql"));
        assert!(!is_sensitive_path("/about"));
        assert!(!is_sensitive_path("/products"));
        assert!(!is_sensitive_path("/api/v1/orders"));
    }

    #[test]
    fn test_is_honeypot_path() {
        assert!(is_honeypot_path("/wp-admin"));
        assert!(is_honeypot_path("/.env"));
        assert!(is_honeypot_path("/phpmyadmin"));
        assert!(is_honeypot_path("/actuator"));
        assert!(is_honeypot_path("/.git"));
        assert!(is_honeypot_path("/backup"));
        assert!(!is_honeypot_path("/api/orders"));
        assert!(!is_honeypot_path("/about"));
    }

    #[test]
    fn test_chain_bonus_vuln_probe_plus_data_exfil() {
        let detector = IntentDetector::new();
        let addr = ip(12);

        // Trigger VulnerabilityProbe: 3 honeypot paths
        detector.analyze(addr, "/wp-admin", "GET");
        detector.analyze(addr, "/.env", "GET");
        detector.analyze(addr, "/phpmyadmin", "GET");

        // Trigger DataExfiltration: 5+ sequential GETs
        detector.analyze(addr, "/api/data/1", "GET");
        detector.analyze(addr, "/api/data/2", "GET");
        detector.analyze(addr, "/api/data/3", "GET");
        detector.analyze(addr, "/api/data/4", "GET");
        let result = detector.analyze(addr, "/api/data/5", "GET");

        // VulnProbe + DataExfil = +0.4
        assert_eq!(
            result.chain_bonus, 0.4,
            "VulnProbe + DataExfil should yield chain bonus of 0.4, got {}",
            result.chain_bonus
        );
    }

    #[test]
    fn test_generic_chain_bonus_two_other_intents() {
        let detector = IntentDetector::new();
        let addr = ip(13);

        // Trigger CredentialStuffing: 3 POST /login
        detector.analyze(addr, "/login", "POST");
        detector.analyze(addr, "/login", "POST");
        detector.analyze(addr, "/login", "POST");

        // Trigger ApiEnumeration: 10+ unique API paths
        for i in 0..11 {
            detector.analyze(addr, &format!("/api/v1/resource{}", i), "GET");
        }

        let result = detector.analyze(addr, "/api/v1/resource11", "GET");

        // CredentialStuffing + ApiEnumeration = generic +0.2
        assert!(
            result.chain_bonus >= 0.2,
            "Generic 2-intent combo should yield at least +0.2, got {}",
            result.chain_bonus
        );
    }

    #[test]
    fn test_multiple_ips_independent() {
        let detector = IntentDetector::new();
        let addr1 = ip(20);
        let addr2 = ip(21);

        // IP 1: normal browsing
        detector.analyze(addr1, "/", "GET");
        detector.analyze(addr1, "/about", "GET");

        // IP 2: reconnaissance
        detector.analyze(addr2, "/login", "GET");
        detector.analyze(addr2, "/admin", "GET");
        let result2 = detector.analyze(addr2, "/config", "GET");

        // IP 1 should have no detections
        let result1 = detector.analyze(addr1, "/contact", "GET");
        assert!(
            result1.intents.is_empty(),
            "IP 1 (normal browsing) should have no detections"
        );

        // IP 2 should have Reconnaissance
        let recon = result2
            .intents
            .iter()
            .find(|d| d.intent == RecognizedIntent::Reconnaissance);
        assert!(
            recon.is_some(),
            "IP 2 should have Reconnaissance detection"
        );
    }
}
