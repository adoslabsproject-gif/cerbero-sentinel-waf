//! Identity Graph (Section C1 -- Sentinel WAF v2.0.0)
//!
//! Probabilistic multi-signal identity resolution that is NAT-safe.
//! Groups requests from the same logical user across IP changes using
//! weighted similarity scoring on multiple signals:
//!
//! | Signal             | Weight | Rationale                              |
//! |--------------------|--------|----------------------------------------|
//! | IP match           | +0.10  | NAT-safe: weakest (shared by many)     |
//! | JA3 hash           | +0.15  | TLS fingerprint (future -- field only)  |
//! | HTTP fingerprint   | +0.25  | Accept/encoding/language headers        |
//! | UA hash            | +0.15  | User-Agent string hash                  |
//! | Behavior hash      | +0.20  | Request pattern hash                    |
//! | Timing signature   | +0.15  | Mean inter-request interval (10% tol)   |
//! | Cookie ID hash     | +0.30  | Strongest -- discriminates NAT users    |
//!
//! Similarity >= 0.55 -> merge into existing identity.
//! Similarity 0.40-0.55 -> weak association (30% risk share, max 5, 30min TTL).
//! Similarity < 0.40 -> new identity (rate-limited per IP and /24 subnet).
//!
//! Dual risk decay (N1):
//! - fast_risk: decay 0.95^minutes (half-life ~14min) -- catches bursts
//! - slow_risk: decay 0.995^minutes (half-life ~138min) -- catches persistent
//! - effective_risk = max(fast_risk, slow_risk * 0.7)
//!
//! All structures are lock-free (DashMap + AtomicU64). Hard cap 10000 identities
//! with priority retention (risk > 0.5 survives eviction). Inverse index for
//! O(K) candidate pre-selection instead of O(N) full scan.

use dashmap::DashMap;
use sentinel_core::sharded_lru::ShardedLru;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Merge threshold: similarity >= this value merges into existing identity
const MERGE_THRESHOLD: f64 = 0.55;

/// Weak association threshold: similarity in [WEAK_THRESHOLD, MERGE_THRESHOLD)
const WEAK_THRESHOLD: f64 = 0.40;

/// Risk share coefficient for weak associations
const WEAK_RISK_SHARE: f64 = 0.30;

/// Maximum weak associations per identity
const MAX_WEAK_ASSOCIATIONS: usize = 5;

/// Weak association TTL (30 minutes)
const WEAK_ASSOCIATION_TTL: Duration = Duration::from_secs(30 * 60);

/// Fast risk decay base (0.95^minutes, half-life ~14min)
const FAST_DECAY_BASE: f64 = 0.95;

/// Slow risk decay base (0.995^minutes, half-life ~138min)
const SLOW_DECAY_BASE: f64 = 0.995;

/// Slow risk scaling factor in effective_risk calculation
const SLOW_RISK_FACTOR: f64 = 0.70;

/// Hard cap on total identities in the graph
const MAX_IDENTITIES: usize = 10_000;

/// Cap del set inner `LogicalIdentity.ips` (IP-per-identità). GEMELLO della classe BG1
/// sull'inner map delle identità: in uno scenario Sybil (1 cookie/fingerprint da milioni
/// di IP) tutti gli IP si correlano alla STESSA identità → `ips` cresce illimitato (OOM).
/// Le identità sono cappate a MAX_IDENTITIES, ma il loro inner set no: cappare la chiave
/// non basta. 4096 ≫ qualunque NAT reale; oltre, si smette di tracciare nuovi IP.
const MAX_IPS_PER_IDENTITY: usize = 4096;

/// LRU eviction: stale after this duration of inactivity
const STALE_AFTER: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Priority retention: identities with risk above this are never evicted
const PRIORITY_RISK_THRESHOLD: f64 = 0.50;

/// Rate limit: max new identities per minute per IP
const MAX_NEW_PER_IP_PER_MINUTE: u64 = 20;

/// Rate limit: max new identities per minute per /24 subnet
const MAX_NEW_PER_SUBNET_PER_MINUTE: u64 = 100;

/// Rate limit window duration
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Capacity HARD delle mappe del rate-limiter di creazione identità (`ShardedLru`,
/// anti-OOM). IP e /24-subnet sono attacker-controlled: sotto IP-rotation le mappe
/// crescevano illimitate FRA una cleanup e l'altra (il `retain` girava solo nel
/// `cleanup()` periodico). Ora il bound è strutturale (evict LRU O(1) all'inserimento)
/// → il rate-limiter che gating la creazione di identità non è più esso stesso un
/// vettore OOM. ~100k IP è ben oltre qualunque traffico legittimo simultaneo.
const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;

/// Timing signature tolerance (10% relative difference) -- reserved for future use
#[allow(dead_code)]
const TIMING_TOLERANCE: f64 = 0.10;

// ─── Similarity weights ──────────────────────────────────────────────────────

const WEIGHT_IP: f64 = 0.10;
/// JA3 weight -- reserved for future TLS fingerprint integration
#[allow(dead_code)]
const WEIGHT_JA3: f64 = 0.15;
const WEIGHT_HTTP_FINGERPRINT: f64 = 0.25;
const WEIGHT_UA: f64 = 0.15;
const WEIGHT_BEHAVIOR: f64 = 0.20;
/// Timing weight -- reserved for future timing signature integration
#[allow(dead_code)]
const WEIGHT_TIMING: f64 = 0.15;
const WEIGHT_COOKIE: f64 = 0.30;

// ─── IdentityId ──────────────────────────────────────────────────────────────

/// Monotonic unique identity identifier (lock-free, wrap around u64)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityId(u64);

impl IdentityId {
    /// Internal value (for testing and serialization)
    pub fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityId({})", self.0)
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}", self.0)
    }
}

// ─── SignalKey ────────────────────────────────────────────────────────────────

/// Signal key for the inverse index: maps a single signal value to the set of
/// identities that share it, enabling O(K) candidate pre-selection.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SignalKey {
    /// JA3 TLS fingerprint hash (future use)
    Ja3(u64),
    /// HTTP fingerprint (Accept/encoding/language headers hash)
    HttpFingerprint(u64),
    /// User-Agent string hash
    UaHash(u64),
    /// Request behavior pattern hash
    BehaviorHash(u64),
    /// Cookie/session ID hash (strongest discriminator)
    CookieIdHash(u64),
}

// ─── IpAssociation ───────────────────────────────────────────────────────────

/// Tracks when and how often an IP has been associated with an identity
#[derive(Debug, Clone)]
pub struct IpAssociation {
    /// First time this IP was seen for this identity
    pub first_seen: Instant,
    /// Last time this IP was seen for this identity
    pub last_seen: Instant,
    /// Total request count from this IP for this identity
    pub request_count: u64,
}

impl IpAssociation {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            first_seen: now,
            last_seen: now,
            request_count: 1,
        }
    }

    fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.request_count += 1;
    }
}

// ─── WeakAssociation ─────────────────────────────────────────────────────────

/// A probabilistic link between two identities that are similar but not similar
/// enough to merge. Shares 30% of risk. Max 5 per identity, expires after 30min.
#[derive(Debug, Clone)]
pub struct WeakAssociation {
    /// Target identity this association points to
    pub target_id: IdentityId,
    /// Similarity score that caused this association (0.40-0.55)
    pub similarity: f64,
    /// Risk share coefficient (fixed at 0.30)
    pub risk_share: f64,
    /// When this association was created
    pub created_at: Instant,
}

impl WeakAssociation {
    fn new(target_id: IdentityId, similarity: f64) -> Self {
        Self {
            target_id,
            similarity,
            risk_share: WEAK_RISK_SHARE,
            created_at: Instant::now(),
        }
    }

    /// Whether this weak association has expired (>30 min)
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > WEAK_ASSOCIATION_TTL
    }
}

// ─── LogicalIdentity ─────────────────────────────────────────────────────────

/// A logical identity grouping requests from the same user across IPs.
/// Uses multiple signals for probabilistic matching and dual-decay risk tracking.
#[derive(Debug)]
pub struct LogicalIdentity {
    /// Unique monotonic identifier
    pub id: IdentityId,
    /// Associated IPs with timing/count metadata
    pub ips: HashMap<IpAddr, IpAssociation>,
    /// JA3 TLS fingerprint hash (future use, field reserved)
    pub ja3_hash: Option<u64>,
    /// HTTP fingerprint (Accept/encoding/language headers hash)
    pub http_fingerprint: u64,
    /// User-Agent string hash
    pub ua_hash: u64,
    /// Request behavior pattern hash
    pub behavior_hash: u64,
    /// Mean inter-request interval in milliseconds (for timing similarity)
    pub timing_signature: f64,
    /// Cookie/session ID hash (strongest NAT discriminator)
    pub cookie_id_hash: Option<u64>,
    /// Fast risk accumulator (decay 0.95^min, half-life ~14min)
    pub fast_risk: f64,
    /// Slow risk accumulator (decay 0.995^min, half-life ~138min)
    pub slow_risk: f64,
    /// Last time risk was updated (for lazy decay)
    pub risk_last_updated: Instant,
    /// First time this identity was seen
    pub first_seen: Instant,
    /// Last time this identity was active
    pub last_seen: Instant,
    /// Weak associations to other identities (max 5, 30min TTL)
    pub weak_associations: Vec<WeakAssociation>,
    /// Optional tenant/org scoping
    pub tenant_id: Option<String>,
}

impl LogicalIdentity {
    /// Create a new identity from the initial request signals
    fn new(
        id: IdentityId,
        ip: IpAddr,
        ua_hash: u64,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
    ) -> Self {
        let now = Instant::now();
        let mut ips = HashMap::new();
        ips.insert(ip, IpAssociation::new());

        Self {
            id,
            ips,
            ja3_hash: None,
            http_fingerprint,
            ua_hash,
            behavior_hash,
            timing_signature: 0.0,
            cookie_id_hash: cookie_hash,
            fast_risk: 0.0,
            slow_risk: 0.0,
            risk_last_updated: now,
            first_seen: now,
            last_seen: now,
            weak_associations: Vec::new(),
            tenant_id: None,
        }
    }

    /// Apply lazy decay to both risk accumulators based on elapsed time
    fn apply_decay(&mut self) {
        let elapsed_minutes = self.risk_last_updated.elapsed().as_secs_f64() / 60.0;
        if elapsed_minutes > 0.0 {
            self.fast_risk *= FAST_DECAY_BASE.powf(elapsed_minutes);
            self.slow_risk *= SLOW_DECAY_BASE.powf(elapsed_minutes);
            self.risk_last_updated = Instant::now();

            // Clamp near-zero values to zero to avoid floating-point dust
            if self.fast_risk < 1e-6 {
                self.fast_risk = 0.0;
            }
            if self.slow_risk < 1e-6 {
                self.slow_risk = 0.0;
            }
        }
    }

    /// Add risk score to both accumulators (call AFTER apply_decay)
    fn add_risk(&mut self, score: f64) {
        self.fast_risk += score;
        self.slow_risk += score;
    }

    /// Calculate effective risk: max(fast_risk, slow_risk * 0.7)
    fn effective_risk(&self) -> f64 {
        self.fast_risk.max(self.slow_risk * SLOW_RISK_FACTOR)
    }

    /// Calculate weighted similarity against a set of request signals
    fn similarity(
        &self,
        ip: IpAddr,
        ua_hash: u64,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
    ) -> f64 {
        let mut score = 0.0;

        // IP match (weakest -- shared in NAT environments)
        if self.ips.contains_key(&ip) {
            score += WEIGHT_IP;
        }

        // NB: JA3 (TLS) e timing NON entrano nel punteggio (RISERVATI): questo layer non
        // riceve né il fingerprint TLS né un timing profiler. I 5 segnali sommati qui
        // (IP+HTTP+UA+behavior+cookie) totalizzano 1.0 → scoring COMPLETO senza di essi
        // (pinnato da fed_weights_sum_to_one). Verranno aggiunti SOLO quando il caller li
        // fornirà davvero, riscalando la soglia. Niente if-stub vuoti (erano no-op).

        // HTTP fingerprint match
        if self.http_fingerprint == http_fingerprint {
            score += WEIGHT_HTTP_FINGERPRINT;
        }

        // UA hash match
        if self.ua_hash == ua_hash {
            score += WEIGHT_UA;
        }

        // Behavior hash match
        if self.behavior_hash == behavior_hash {
            score += WEIGHT_BEHAVIOR;
        }

        // Cookie ID hash match (strongest -- discriminates NAT users)
        if let (Some(mine), Some(theirs)) = (self.cookie_id_hash, cookie_hash) {
            if mine == theirs {
                score += WEIGHT_COOKIE;
            }
        }

        score
    }

    /// Touch this identity: update last_seen and record IP
    fn touch(&mut self, ip: IpAddr) {
        self.last_seen = Instant::now();
        match self.ips.get_mut(&ip) {
            Some(assoc) => assoc.touch(),
            None => {
                // Cap anti-OOM (LIDENT-IPS): oltre MAX_IPS_PER_IDENTITY non si traccia
                // un nuovo IP (l'identità resta comunque "toccata" e rilevata ad alta
                // churn). Senza, una Sybil con milioni di IP gonfia `ips` all'infinito.
                if self.ips.len() < MAX_IPS_PER_IDENTITY {
                    self.ips.insert(ip, IpAssociation::new());
                }
            }
        }
    }

    /// Whether this identity is stale (no activity for > 1h)
    fn is_stale(&self) -> bool {
        self.last_seen.elapsed() > STALE_AFTER
    }

    /// Whether this identity has high risk (priority retention)
    fn is_priority(&self) -> bool {
        self.effective_risk() > PRIORITY_RISK_THRESHOLD
    }

    /// Remove expired weak associations and enforce max count
    fn prune_weak_associations(&mut self) {
        self.weak_associations.retain(|wa| !wa.is_expired());
        // If still over limit after expiry pruning, drop lowest similarity
        while self.weak_associations.len() > MAX_WEAK_ASSOCIATIONS {
            let min_idx = self
                .weak_associations
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.similarity.partial_cmp(&b.similarity).unwrap())
                .map(|(i, _)| i);
            if let Some(idx) = min_idx {
                self.weak_associations.remove(idx);
            } else {
                break;
            }
        }
    }

    /// Add a weak association, enforcing max 5 and replacing lowest similarity if needed
    fn add_weak_association(&mut self, target_id: IdentityId, similarity: f64) {
        // Do not create duplicate associations to the same target
        if self.weak_associations.iter().any(|wa| wa.target_id == target_id) {
            return;
        }

        if self.weak_associations.len() >= MAX_WEAK_ASSOCIATIONS {
            // Replace lowest similarity if the new one is stronger
            let min_idx = self
                .weak_associations
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| a.similarity.partial_cmp(&b.similarity).unwrap())
                .map(|(i, _)| i);
            if let Some(idx) = min_idx {
                if self.weak_associations[idx].similarity < similarity {
                    self.weak_associations[idx] = WeakAssociation::new(target_id, similarity);
                }
            }
        } else {
            self.weak_associations.push(WeakAssociation::new(target_id, similarity));
        }
    }
}

// ─── IdentityProcessResult ──────────────────────────────────────────────────

/// Result returned from IdentityGraph::process() to the behavioral analysis layer
#[derive(Debug, Clone)]
pub struct IdentityProcessResult {
    /// Whether the request was matched to an existing tracked identity
    pub is_tracked: bool,
    /// Whether a weak association was created (not a full merge)
    pub has_weak_association: bool,
    /// Whether identity churn was detected (new identity created despite rate limit)
    pub identity_churn_detected: bool,
    /// Effective risk for this identity after decay + accumulation
    pub effective_risk: f64,
}

// ─── Rate Limiter ────────────────────────────────────────────────────────────

/// Per-IP and per-subnet rate limiter for identity creation.
///
/// Mappe `ShardedLru` (bound HARD realtime, evict LRU O(1)): IP/subnet sono
/// attacker-controlled. Un IP/subnet sfrattato perché LRU = idle riparte da
/// `count=0`, ma è innocuo (un attaccante ATTIVO resta recente → non sfrattato →
/// rate-limitato correttamente).
struct CreationRateLimiter {
    /// IP -> (count, window_start)
    per_ip: ShardedLru<IpAddr, (u64, Instant)>,
    /// /24 subnet key -> (count, window_start)
    per_subnet: ShardedLru<u32, (u64, Instant)>,
}

impl CreationRateLimiter {
    fn new() -> Self {
        Self {
            per_ip: ShardedLru::new(MAX_RATE_LIMIT_ENTRIES),
            per_subnet: ShardedLru::new(MAX_RATE_LIMIT_ENTRIES),
        }
    }

    /// Check and increment rate limit for the given IP.
    /// Returns true if identity creation is allowed, false if rate-limited.
    fn check_and_increment(&self, ip: IpAddr) -> bool {
        let now = Instant::now();

        // Per-IP check. `with_entry_mut`: get-or-create + evict LRU O(1) se lo shard
        // è pieno (bound HARD realtime), tutto sotto un solo lock dello shard.
        let ip_allowed = self.per_ip.with_entry_mut(ip, || (0, now), |entry| {
            let (count, window_start) = entry;
            if now.duration_since(*window_start) > RATE_LIMIT_WINDOW {
                *count = 0;
                *window_start = now;
            }
            if *count >= MAX_NEW_PER_IP_PER_MINUTE {
                false
            } else {
                *count += 1;
                true
            }
        });

        if !ip_allowed {
            return false;
        }

        // Per-subnet (/24) check
        let subnet_key = Self::subnet_key(ip);
        self.per_subnet.with_entry_mut(subnet_key, || (0, now), |entry| {
            let (count, window_start) = entry;
            if now.duration_since(*window_start) > RATE_LIMIT_WINDOW {
                *count = 0;
                *window_start = now;
            }
            if *count >= MAX_NEW_PER_SUBNET_PER_MINUTE {
                false
            } else {
                *count += 1;
                true
            }
        })
    }

    /// Extract a /24 subnet key from an IP address (first 3 octets for IPv4,
    /// first 6 groups for IPv6 -- simplified hash for IPv6).
    fn subnet_key(ip: IpAddr) -> u32 {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                u32::from_be_bytes([octets[0], octets[1], octets[2], 0])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                // Hash first 3 segments (48 bits) into u32
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                segments[0].hash(&mut hasher);
                segments[1].hash(&mut hasher);
                segments[2].hash(&mut hasher);
                hasher.finish() as u32
            }
        }
    }

    /// RECLAIM delle entry scadute (libera RAM prima che la LRU le sfratti). Il bound
    /// NON dipende più da questo retain: è strutturale in `ShardedLru`.
    fn cleanup(&self) {
        let now = Instant::now();
        self.per_ip
            .retain(|_, (_, start)| now.duration_since(*start) <= RATE_LIMIT_WINDOW * 2);
        self.per_subnet
            .retain(|_, (_, start)| now.duration_since(*start) <= RATE_LIMIT_WINDOW * 2);
    }
}

// ─── IdentityGraph ───────────────────────────────────────────────────────────

/// Thread-safe, lock-free identity resolution graph.
///
/// Uses DashMap for all mutable state. Inverse index on signal values enables
/// O(K) candidate pre-selection (K = number of identities sharing a signal)
/// instead of O(N) full scan across all identities.
pub struct IdentityGraph {
    /// Primary storage: IdentityId -> LogicalIdentity
    identities: DashMap<IdentityId, LogicalIdentity>,
    /// Inverse index: signal value -> list of identity IDs sharing that signal
    signal_to_identity: DashMap<SignalKey, Vec<IdentityId>>,
    /// Lock-free monotonic ID generator
    next_id: AtomicU64,
    /// Rate limiter for identity creation
    rate_limiter: CreationRateLimiter,
    /// Generic buckets: IPs that exceed rate limits are assigned to a single
    /// catch-all identity per IP. `ShardedLru` (bound HARD realtime): la mappa è
    /// IP-keyed (attacker-controlled) e `use_generic_bucket` inseriva in `identities`
    /// BYPASSANDO il cap inline → senza bound cresceva oltre MAX_IDENTITIES fra le
    /// cleanup. L'eviction è orphan-aware (vedi `use_generic_bucket`): sfrattando un
    /// IP→id si rimuove anche l'identità catch-all da `identities` → niente leak e il
    /// cap non è più bypassato (generic identities ≤ capacity di questa mappa).
    generic_buckets: ShardedLru<IpAddr, IdentityId>,
}

impl IdentityGraph {
    /// Create a new empty identity graph
    pub fn new() -> Self {
        Self {
            identities: DashMap::new(),
            signal_to_identity: DashMap::new(),
            next_id: AtomicU64::new(1),
            rate_limiter: CreationRateLimiter::new(),
            generic_buckets: ShardedLru::new(MAX_IDENTITIES),
        }
    }

    /// Generate the next monotonic identity ID (lock-free)
    fn next_identity_id(&self) -> IdentityId {
        IdentityId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Hash a string using DefaultHasher (consistent with lib.rs hash_string)
    fn hash_string(s: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    // ─── Inverse index management ────────────────────────────────────────

    /// Register all non-None signals of an identity in the inverse index
    fn register_signals(&self, identity: &LogicalIdentity) {
        let id = identity.id;

        if let Some(ja3) = identity.ja3_hash {
            self.signal_to_identity
                .entry(SignalKey::Ja3(ja3))
                .or_default()
                .push(id);
        }

        self.signal_to_identity
            .entry(SignalKey::HttpFingerprint(identity.http_fingerprint))
            .or_default()
            .push(id);

        self.signal_to_identity
            .entry(SignalKey::UaHash(identity.ua_hash))
            .or_default()
            .push(id);

        self.signal_to_identity
            .entry(SignalKey::BehaviorHash(identity.behavior_hash))
            .or_default()
            .push(id);

        if let Some(cookie) = identity.cookie_id_hash {
            self.signal_to_identity
                .entry(SignalKey::CookieIdHash(cookie))
                .or_default()
                .push(id);
        }
    }

    /// Remove an identity ID from all inverse index entries
    fn unregister_signals(&self, identity_id: IdentityId) {
        self.signal_to_identity.iter_mut().for_each(|mut entry| {
            entry.value_mut().retain(|id| *id != identity_id);
        });
    }

    /// Collect candidate identity IDs from the inverse index based on input signals.
    /// Returns a deduplicated set of IDs that share at least one signal.
    fn candidate_ids(
        &self,
        ua_hash: u64,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
    ) -> HashSet<IdentityId> {
        let mut candidates = HashSet::new();

        // Collect from each signal key
        let keys: Vec<SignalKey> = {
            let mut k = vec![
                SignalKey::HttpFingerprint(http_fingerprint),
                SignalKey::UaHash(ua_hash),
                SignalKey::BehaviorHash(behavior_hash),
            ];
            if let Some(cookie) = cookie_hash {
                k.push(SignalKey::CookieIdHash(cookie));
            }
            k
        };

        for key in &keys {
            if let Some(ids) = self.signal_to_identity.get(key) {
                for id in ids.value() {
                    candidates.insert(*id);
                }
            }
        }

        candidates
    }

    // ─── Main entry point ────────────────────────────────────────────────

    /// Process an incoming request and resolve it to an identity.
    ///
    /// This is the main entry point called by `lib.rs` BehavioralAnalysis::analyze().
    /// Computes UA hash from the raw string, uses the inverse index for O(K)
    /// candidate pre-selection, and applies weighted similarity scoring to find
    /// the best match.
    ///
    /// # Parameters
    /// - `ip`: Client IP address
    /// - `ua`: User-Agent header string (hashed internally)
    /// - `http_fingerprint`: Hash of Accept/encoding/language headers
    /// - `behavior_hash`: Hash of request pattern
    /// - `cookie_hash`: Optional cookie/session ID hash
    /// - `current_score`: Current behavioral risk score for this request
    pub fn process(
        &self,
        ip: IpAddr,
        ua: &str,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
        current_score: f64,
    ) -> IdentityProcessResult {
        let ua_hash = Self::hash_string(ua);

        // ── Step 1: Candidate pre-selection via inverse index (O(K)) ─────
        let candidates = self.candidate_ids(ua_hash, http_fingerprint, behavior_hash, cookie_hash);

        // ── Step 2: Score all candidates and find the best match ─────────
        let mut best_match: Option<(IdentityId, f64)> = None;

        for candidate_id in &candidates {
            if let Some(identity) = self.identities.get(candidate_id) {
                let sim = identity.similarity(
                    ip,
                    ua_hash,
                    http_fingerprint,
                    behavior_hash,
                    cookie_hash,
                );
                match best_match {
                    Some((_, best_sim)) if sim > best_sim => {
                        best_match = Some((*candidate_id, sim));
                    }
                    None => {
                        best_match = Some((*candidate_id, sim));
                    }
                    _ => {}
                }
            }
        }

        // ── Step 3: Decision based on similarity score ───────────────────

        // Case A: Strong match (>= 0.55) -- merge into existing identity
        if let Some((match_id, sim)) = best_match {
            if sim >= MERGE_THRESHOLD {
                return self.merge_into_identity(match_id, ip, current_score);
            }
        }

        // Case B: Weak match (0.40-0.55) -- create weak association
        if let Some((match_id, sim)) = best_match {
            if sim >= WEAK_THRESHOLD {
                return self.create_weak_association(
                    match_id,
                    ip,
                    ua_hash,
                    http_fingerprint,
                    behavior_hash,
                    cookie_hash,
                    current_score,
                    sim,
                );
            }
        }

        // Case C: No match (< 0.40) -- create new identity (rate-limited)
        self.create_new_identity(
            ip,
            ua_hash,
            http_fingerprint,
            behavior_hash,
            cookie_hash,
            current_score,
        )
    }

    /// Merge a request into an existing identity (similarity >= 0.55)
    fn merge_into_identity(
        &self,
        identity_id: IdentityId,
        ip: IpAddr,
        current_score: f64,
    ) -> IdentityProcessResult {
        if let Some(mut identity) = self.identities.get_mut(&identity_id) {
            identity.apply_decay();
            identity.add_risk(current_score);
            identity.touch(ip);

            let effective = identity.effective_risk();
            let has_weak = !identity.weak_associations.is_empty();

            IdentityProcessResult {
                is_tracked: true,
                has_weak_association: has_weak,
                identity_churn_detected: false,
                effective_risk: effective,
            }
        } else {
            // Identity was evicted between candidate lookup and merge -- treat as new
            self.create_new_identity(ip, 0, 0, 0, None, current_score)
        }
    }

    /// Create a weak association between a new request and a partially-matching identity
    fn create_weak_association(
        &self,
        match_id: IdentityId,
        ip: IpAddr,
        ua_hash: u64,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
        current_score: f64,
        similarity: f64,
    ) -> IdentityProcessResult {
        // Create a new identity for this request
        let new_result = self.create_new_identity(
            ip,
            ua_hash,
            http_fingerprint,
            behavior_hash,
            cookie_hash,
            current_score,
        );

        // Find the ID of the newly created identity (the last ID generated)
        let new_id = IdentityId(self.next_id.load(Ordering::Relaxed) - 1);

        // Add weak association from the matching identity to the new one
        if let Some(mut match_identity) = self.identities.get_mut(&match_id) {
            match_identity.add_weak_association(new_id, similarity);
        }

        // Add weak association from the new identity to the matching one
        if let Some(mut new_identity) = self.identities.get_mut(&new_id) {
            new_identity.add_weak_association(match_id, similarity);
        }

        // Compute effective risk including shared risk from weak association
        let shared_risk = if let Some(match_identity) = self.identities.get(&match_id) {
            let mut cloned = LogicalIdentity {
                id: match_identity.id,
                ips: HashMap::new(),
                ja3_hash: None,
                http_fingerprint: 0,
                ua_hash: 0,
                behavior_hash: 0,
                timing_signature: 0.0,
                cookie_id_hash: None,
                fast_risk: match_identity.fast_risk,
                slow_risk: match_identity.slow_risk,
                risk_last_updated: match_identity.risk_last_updated,
                first_seen: match_identity.first_seen,
                last_seen: match_identity.last_seen,
                weak_associations: Vec::new(),
                tenant_id: None,
            };
            cloned.apply_decay();
            cloned.effective_risk() * WEAK_RISK_SHARE
        } else {
            0.0
        };

        IdentityProcessResult {
            is_tracked: new_result.is_tracked,
            has_weak_association: true,
            identity_churn_detected: new_result.identity_churn_detected,
            effective_risk: new_result.effective_risk + shared_risk,
        }
    }

    /// Create a new identity (if rate limit allows, else use generic bucket)
    fn create_new_identity(
        &self,
        ip: IpAddr,
        ua_hash: u64,
        http_fingerprint: u64,
        behavior_hash: u64,
        cookie_hash: Option<u64>,
        current_score: f64,
    ) -> IdentityProcessResult {
        // Check rate limit
        if !self.rate_limiter.check_and_increment(ip) {
            // Rate-limited: use generic bucket for this IP
            return self.use_generic_bucket(ip, current_score);
        }

        // Check hard cap
        if self.identities.len() >= MAX_IDENTITIES {
            // Try eviction first
            self.evict_stale_identities();

            // If still over cap, force eviction of oldest non-priority
            if self.identities.len() >= MAX_IDENTITIES {
                self.force_evict_oldest();
            }

            // If STILL over cap (all are priority), use generic bucket
            if self.identities.len() >= MAX_IDENTITIES {
                return self.use_generic_bucket(ip, current_score);
            }
        }

        let id = self.next_identity_id();
        let mut identity = LogicalIdentity::new(
            id,
            ip,
            ua_hash,
            http_fingerprint,
            behavior_hash,
            cookie_hash,
        );
        identity.add_risk(current_score);
        let effective = identity.effective_risk();

        // Register in inverse index before inserting
        self.register_signals(&identity);

        self.identities.insert(id, identity);

        IdentityProcessResult {
            is_tracked: true,
            has_weak_association: false,
            identity_churn_detected: false,
            effective_risk: effective,
        }
    }

    /// Route a rate-limited IP to a generic bucket identity
    fn use_generic_bucket(&self, ip: IpAddr, current_score: f64) -> IdentityProcessResult {
        // Bucket esistente CON identità ancora viva? (peek: non promuove inutilmente)
        let existing = self
            .generic_buckets
            .with_peek(&ip, |o| o.copied())
            .filter(|id| self.identities.contains_key(id));

        let bucket_id = match existing {
            Some(id) => id,
            None => {
                // Crea un'identità catch-all fresca per questo IP.
                let id = self.next_identity_id();
                let identity = LogicalIdentity::new(id, ip, 0, 0, 0, None);
                self.identities.insert(id, identity);
                // `put` inserisce/rimpiazza e ritorna l'eventuale entry SFRATTATA (shard
                // LRU pieno) o la precedente per lo stesso IP. EVICTION-AWARE: rimuovo
                // l'identità orfana dalla mappa primaria → niente leak e il cap di
                // `identities` non è più bypassato (generic identities ≤ capacity).
                if let Some((_old_ip, old_id)) = self.generic_buckets.put(ip, id) {
                    if old_id != id {
                        self.identities.remove(&old_id);
                        // ORPHAN1: simmetria con le altre remove (righe cleanup) — deregistra
                        // gli eventuali signal dell'identità sfrattata dall'indice inverso.
                        // Le catch-all oggi non registrano signal (no-op), ma la guardia
                        // rende l'invariante robusta se in futuro lo facessero.
                        self.unregister_signals(old_id);
                    }
                }
                id
            }
        };

        if let Some(mut identity) = self.identities.get_mut(&bucket_id) {
            identity.apply_decay();
            identity.add_risk(current_score);
            identity.touch(ip);

            IdentityProcessResult {
                is_tracked: true,
                has_weak_association: false,
                identity_churn_detected: true,
                effective_risk: identity.effective_risk(),
            }
        } else {
            // Difensivo: l'identità appena garantita risulta assente (race improbabile).
            // Calcolo un risultato transitorio SENZA inserire (niente leak) — sarà
            // ricreata al giro successivo.
            let mut identity = LogicalIdentity::new(self.next_identity_id(), ip, 0, 0, 0, None);
            identity.add_risk(current_score);
            IdentityProcessResult {
                is_tracked: true,
                has_weak_association: false,
                identity_churn_detected: true,
                effective_risk: identity.effective_risk(),
            }
        }
    }

    // ─── Eviction ────────────────────────────────────────────────────────

    /// Remove stale identities (no activity > 1h), preserving high-risk ones
    fn evict_stale_identities(&self) {
        self.identities.retain(|_, identity| {
            if identity.is_stale() && !identity.is_priority() {
                // Clean up inverse index for this identity
                // (done in bulk cleanup, not here for performance)
                false
            } else {
                true
            }
        });
    }

    /// Force eviction of the oldest non-priority identities (when hard cap exceeded)
    fn force_evict_oldest(&self) {
        let target = self.identities.len().saturating_sub(MAX_IDENTITIES / 10); // Free 10%
        if target == 0 {
            return;
        }

        // Collect non-priority identities sorted by last_seen
        let mut eviction_candidates: Vec<(IdentityId, Instant)> = self
            .identities
            .iter()
            .filter(|entry| !entry.value().is_priority())
            .map(|entry| (entry.value().id, entry.value().last_seen))
            .collect();

        eviction_candidates.sort_by(|a, b| a.1.cmp(&b.1)); // Oldest first

        let to_remove = self.identities.len().saturating_sub(MAX_IDENTITIES - MAX_IDENTITIES / 10);
        for (id, _) in eviction_candidates.iter().take(to_remove) {
            self.unregister_signals(*id);
            self.identities.remove(id);
        }

        // If STILL over cap (all priority), force evict oldest regardless
        if self.identities.len() >= MAX_IDENTITIES {
            let mut all_by_age: Vec<(IdentityId, Instant)> = self
                .identities
                .iter()
                .map(|entry| (entry.value().id, entry.value().last_seen))
                .collect();

            all_by_age.sort_by(|a, b| a.1.cmp(&b.1));

            let must_remove = self.identities.len() - MAX_IDENTITIES + 1;
            for (id, _) in all_by_age.iter().take(must_remove) {
                self.unregister_signals(*id);
                self.identities.remove(id);
            }
        }
    }

    // ─── Cleanup (public, called by BehavioralAnalysis::cleanup()) ───────

    /// Periodic cleanup of the identity graph.
    ///
    /// - Remove expired weak associations (> 30min)
    /// - LRU eviction of stale identities (> 1h no activity)
    /// - Enforce hard cap (10000 identities)
    /// - Clean stale entries from inverse index
    /// - Clean rate limiter state
    pub fn cleanup(&self) {
        // 1. Prune expired weak associations from all identities
        self.identities.iter_mut().for_each(|mut entry| {
            entry.value_mut().prune_weak_associations();
        });

        // 2. Evict stale identities (> 1h, non-priority)
        self.evict_stale_identities();

        // 3. Enforce hard cap
        if self.identities.len() > MAX_IDENTITIES {
            self.force_evict_oldest();
        }

        // 4. Clean stale entries from inverse index (remove IDs that no longer exist)
        let active_ids: HashSet<IdentityId> = self
            .identities
            .iter()
            .map(|entry| entry.value().id)
            .collect();

        self.signal_to_identity.retain(|_, ids| {
            ids.retain(|id| active_ids.contains(id));
            !ids.is_empty()
        });

        // 5. Clean stale generic bucket entries
        self.generic_buckets.retain(|_, id| active_ids.contains(&*id));

        // 6. Clean rate limiter
        self.rate_limiter.cleanup();
    }

    // ─── Observability ───────────────────────────────────────────────────

    /// Total number of tracked identities
    pub fn tracked_identities(&self) -> usize {
        self.identities.len()
    }

    /// Number of entries in the inverse index
    pub fn signal_index_size(&self) -> usize {
        self.signal_to_identity.len()
    }

    /// Number of generic bucket entries
    pub fn generic_bucket_count(&self) -> usize {
        self.generic_buckets.len()
    }
}

impl Default for IdentityGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: create IpAddr from the last octet
    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// CONTRATTO anti-aspirazionale: i 5 segnali REALMENTE alimentati in `similarity`
    /// (IP+HTTP+UA+behavior+cookie) sommano a 1.0 → lo scoring è COMPLETO da solo. JA3 e
    /// timing sono RISERVATI e NON nel punteggio (questo layer non riceve TLS/timing). Se
    /// qualcuno li cablasse senza riscalare, o cambiasse un peso, questo test diventa rosso.
    #[test]
    fn fed_weights_sum_to_one_ja3_and_timing_reserved_outside() {
        let fed = WEIGHT_IP + WEIGHT_HTTP_FINGERPRINT + WEIGHT_UA + WEIGHT_BEHAVIOR + WEIGHT_COOKIE;
        assert!(
            (fed - 1.0).abs() < 1e-9,
            "i 5 segnali alimentati devono sommare a 1.0 (scoring completo senza JA3/timing), trovato {fed}"
        );
        // JA3/timing esistono come riservati ma, se sommati, sforerebbero 1.0 → ecco perché
        // restano FUORI dal punteggio finché non c'è il dato reale + riscalatura soglia.
        assert!(WEIGHT_JA3 > 0.0 && WEIGHT_TIMING > 0.0);
        assert!(fed + WEIGHT_JA3 + WEIGHT_TIMING > 1.0);
    }

    // ─── Test 1: New identity creation ───────────────────────────────────

    #[test]
    fn test_new_identity_creation() {
        let graph = IdentityGraph::new();

        let result = graph.process(ip(1), "Mozilla/5.0 Chrome", 0xAABB, 0xCCDD, None, 0.0);

        assert!(result.is_tracked, "New identity should be tracked");
        assert!(!result.has_weak_association, "New identity should have no weak associations");
        assert!(!result.identity_churn_detected, "First identity should not be churn");
        assert_eq!(graph.tracked_identities(), 1, "Should have exactly 1 identity");
    }

    // ─── Test 2: Identity matching by fingerprint ────────────────────────

    #[test]
    fn test_identity_matching_by_fingerprint() {
        let graph = IdentityGraph::new();

        // First request establishes identity
        let _ = graph.process(
            ip(1),
            "Mozilla/5.0 Chrome",
            0xAABB,
            0xCCDD,
            Some(0xEEFF),
            0.1,
        );
        assert_eq!(graph.tracked_identities(), 1);

        // Second request from DIFFERENT IP but same fingerprints + cookie
        // HTTP fingerprint (0.25) + UA (0.15) + behavior (0.20) + cookie (0.30) = 0.90 >= 0.55
        let result = graph.process(
            ip(2), // Different IP
            "Mozilla/5.0 Chrome",
            0xAABB,
            0xCCDD,
            Some(0xEEFF),
            0.2,
        );

        assert!(result.is_tracked, "Should match existing identity");
        assert_eq!(
            graph.tracked_identities(),
            1,
            "Should still have 1 identity (merged)"
        );
    }

    // ─── Test 3: NAT-safe -- IP+UA alone NOT enough to merge ─────────────

    #[test]
    fn test_nat_safe_ip_ua_alone_not_enough() {
        let graph = IdentityGraph::new();

        // First request
        let _ = graph.process(ip(1), "Mozilla/5.0 Chrome", 0xAABB, 0xCCDD, Some(0x1111), 0.0);

        // Second request: same IP + same UA, but DIFFERENT fingerprint, behavior, and cookie
        // IP match: 0.10, UA match: 0.15 => total 0.25 < 0.40
        // This should create a new identity
        let result = graph.process(
            ip(1),
            "Mozilla/5.0 Chrome",
            0x9999, // Different HTTP fingerprint
            0x8888, // Different behavior hash
            Some(0x7777), // Different cookie
            0.0,
        );

        assert!(result.is_tracked, "Should be tracked (new identity)");
        assert!(!result.has_weak_association, "0.25 < 0.40 -- no weak association");
        assert_eq!(
            graph.tracked_identities(),
            2,
            "Should have 2 separate identities (NAT-safe)"
        );
    }

    // ─── Test 4: Cookie discriminates NAT users ──────────────────────────

    #[test]
    fn test_cookie_discriminates_nat_users() {
        let graph = IdentityGraph::new();

        // User A behind NAT: same IP, same UA, same HTTP fingerprint, same behavior
        let _ = graph.process(ip(1), "Chrome/131", 0xAABB, 0xCCDD, Some(0x1111), 0.0);

        // User B behind same NAT: same IP, same UA, same fingerprint, same behavior, DIFFERENT cookie
        // IP: 0.10 + HTTP: 0.25 + UA: 0.15 + Behavior: 0.20 = 0.70, but cookie mismatch
        // Since cookie_id_hash differs, the cookie weight is not added.
        // 0.70 >= 0.55 -- this would merge WITHOUT cookie discrimination.
        // With cookie present and mismatching, the identity still merges at 0.70
        // because the cookie weight is additive only when matching.
        //
        // To truly discriminate: cookies must be DIFFERENT and signal values must be
        // below threshold without cookie. Since 0.70 >= 0.55, they DO merge.
        //
        // The cookie's power is ADDITIVE: it pushes borderline cases over the merge
        // threshold. For NAT discrimination, the key insight is:
        // if signals WITHOUT cookie are below threshold (e.g., only IP+UA = 0.25)
        // then different cookies keep users separate.
        let _ = graph.process(ip(1), "Chrome/131", 0xAABB, 0xCCDD, Some(0x2222), 0.0);

        // Now test the real NAT scenario: partial signal match where cookie is the deciding factor
        let graph2 = IdentityGraph::new();

        // User A: unique signals + cookie
        let _ = graph2.process(ip(1), "Chrome/131", 0xA1, 0xB1, Some(0xC1), 0.0);

        // User B: same IP, same UA, DIFFERENT http_fingerprint, behavior, cookie
        // IP: 0.10 + UA: 0.15 = 0.25 < 0.40 -- separate identity
        let _ = graph2.process(ip(1), "Chrome/131", 0xA2, 0xB2, Some(0xC2), 0.0);

        assert_eq!(
            graph2.tracked_identities(),
            2,
            "Different cookies + different fingerprints should keep users separate behind NAT"
        );

        // User C: same IP, same UA, same http_fingerprint, same behavior, SAME cookie as User A
        // IP: 0.10 + UA: 0.15 + HTTP: 0.25 + Behavior: 0.20 + Cookie: 0.30 = 1.00 >= 0.55
        let _ = graph2.process(ip(1), "Chrome/131", 0xA1, 0xB1, Some(0xC1), 0.0);

        assert_eq!(
            graph2.tracked_identities(),
            2,
            "Same cookie + same signals should merge back into User A"
        );
    }

    // ─── Test 5: Dual risk decay (verify half-lives) ─────────────────────

    #[test]
    fn test_dual_risk_decay() {
        let graph = IdentityGraph::new();
        let initial_risk = 1.0;

        let _ = graph.process(ip(1), "ua", 0xAA, 0xBB, Some(0xCC), initial_risk);

        // Get the identity and manually set the risk_last_updated to simulate time passing
        let id = IdentityId(1);
        if let Some(mut identity) = graph.identities.get_mut(&id) {
            // Simulate 14 minutes elapsed (approximate fast_risk half-life)
            // 0.95^14 = 0.4877 (approximately half)
            let fast_14min = FAST_DECAY_BASE.powf(14.0);
            assert!(
                (fast_14min - 0.4877).abs() < 0.01,
                "Fast decay at 14min should be ~0.49, got {}",
                fast_14min
            );

            // Simulate 138 minutes elapsed (approximate slow_risk half-life)
            // 0.995^138 = 0.5007 (approximately half)
            let slow_138min = SLOW_DECAY_BASE.powf(138.0);
            assert!(
                (slow_138min - 0.5007).abs() < 0.01,
                "Slow decay at 138min should be ~0.50, got {}",
                slow_138min
            );

            // Verify effective_risk formula: max(fast, slow * 0.7)
            identity.fast_risk = 0.3;
            identity.slow_risk = 0.8;
            let effective = identity.effective_risk();
            // max(0.3, 0.8 * 0.7) = max(0.3, 0.56) = 0.56
            assert!(
                (effective - 0.56).abs() < 1e-6,
                "effective_risk should be max(0.3, 0.56) = 0.56, got {}",
                effective
            );

            // When fast > slow * 0.7
            identity.fast_risk = 0.9;
            identity.slow_risk = 0.5;
            let effective2 = identity.effective_risk();
            // max(0.9, 0.5 * 0.7) = max(0.9, 0.35) = 0.9
            assert!(
                (effective2 - 0.9).abs() < 1e-6,
                "effective_risk should be max(0.9, 0.35) = 0.9, got {}",
                effective2
            );
        } else {
            panic!("Identity not found in graph");
        };
    }

    // ─── Test 6: Weak association (0.40-0.55) ────────────────────────────

    #[test]
    fn test_weak_association() {
        let graph = IdentityGraph::new();

        // First request establishes identity with specific signals
        let _ = graph.process(ip(1), "Chrome/131", 0xA1, 0xB1, Some(0xC1), 0.5);

        // Second request: partial match that falls in weak range (0.40-0.55)
        // Same HTTP fingerprint (0.25) + same UA (0.15) = 0.40 (exactly at weak threshold)
        // Different IP, different behavior, different cookie
        let result = graph.process(ip(2), "Chrome/131", 0xA1, 0xDDDD, Some(0xEEEE), 0.1);

        assert!(result.has_weak_association, "Should create weak association for similarity in [0.40, 0.55)");
        assert_eq!(
            graph.tracked_identities(),
            2,
            "Should have 2 identities (not merged, weak associated)"
        );

        // Verify weak association exists on the original identity
        let id1 = IdentityId(1);
        if let Some(identity) = graph.identities.get(&id1) {
            assert!(
                !identity.weak_associations.is_empty(),
                "First identity should have a weak association"
            );
            assert!(
                identity.weak_associations[0].risk_share == WEAK_RISK_SHARE,
                "Weak association risk_share should be {}",
                WEAK_RISK_SHARE
            );
        };
    }

    // ─── Test 7: Rate limiting per IP ────────────────────────────────────

    #[test]
    fn test_rate_limiting_per_ip() {
        let graph = IdentityGraph::new();

        // Create 20 identities from the same IP (at the limit)
        for i in 0..20 {
            let fp = 0x1000 + i as u64;
            let bh = 0x2000 + i as u64;
            let ck = 0x3000 + i as u64;
            let _ = graph.process(ip(1), &format!("UA-{}", i), fp, bh, Some(ck), 0.0);
        }

        // The 21st should be rate-limited and go to generic bucket
        let result = graph.process(ip(1), "UA-20", 0x9999, 0x8888, Some(0x7777), 0.1);

        assert!(
            result.identity_churn_detected,
            "21st identity from same IP should trigger churn detection"
        );
        assert!(
            graph.generic_bucket_count() > 0,
            "Should have a generic bucket entry"
        );
    }

    /// 🚨 OOM: le mappe del rate-limiter (`per_ip`/`per_subnet`) sono bounded in TEMPO
    /// REALE sotto IP-rotation (`ShardedLru` evict-LRU O(1)), NON solo via il `cleanup()`
    /// periodico. Pre-fix: erano `DashMap` con cap enforced SOLO nel retain periodico →
    /// fra una cleanup e l'altra un flood di IP distinti cresceva illimitato = OOM. È il
    /// rate-limiter che gating la creazione di identità: se è esso stesso DoS-abile, il
    /// gating non protegge. Test sul componente isolato per saturare il bound velocemente.
    #[test]
    fn rate_limiter_maps_bounded_realtime_under_ip_rotation() {
        // cap multiplo dei 16 shard → capacity()==cap; 5000 IP distinti saturano per_ip.
        let cap = 64;
        let rl = CreationRateLimiter {
            per_ip: ShardedLru::new(cap),
            per_subnet: ShardedLru::new(cap),
        };
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            // 192.0.X.Y → 5000 IP distinti; subnet /24 = 192.0.X.0 (~20 distinte).
            let addr = IpAddr::V4(Ipv4Addr::new(192, b[1], b[2], b[3]));
            rl.check_and_increment(addr);
        }
        // per_ip: == cap (pieno) → uccide sia "unbounded" (>cap) sia la false-green
        // "non-inserisce-mai" (len==0 <= cap passerebbe).
        assert_eq!(rl.per_ip.capacity(), cap);
        assert_eq!(
            rl.per_ip.len(),
            cap,
            "OOM: per_ip non bounded realtime (got {})",
            rl.per_ip.len()
        );
        // per_subnet: bounded (poche subnet distinte → sotto cap, comunque mai oltre).
        assert!(
            rl.per_subnet.len() <= cap,
            "OOM: per_subnet non bounded (got {})",
            rl.per_subnet.len()
        );
    }

    /// 🚨 OOM + LEAK: `generic_buckets` è bounded realtime (`ShardedLru`) E l'eviction è
    /// orphan-aware → l'identità catch-all è rimossa da `identities` quando il bucket è
    /// sfrattato. Pre-fix: `use_generic_bucket` inseriva in `identities` BYPASSANDO il
    /// cap inline → sotto flood di IP rate-limited `identities` cresceva oltre
    /// MAX_IDENTITIES + accumulo di orfani. Mutation-verify: togliendo
    /// `identities.remove(&old_id)` → `identities.len()` esplode a 5000 invece di == cap.
    #[test]
    fn generic_buckets_bounded_and_orphan_free() {
        let cap = 64; // multiplo dei 16 shard → capacity()==cap
        let graph = IdentityGraph {
            identities: DashMap::new(),
            signal_to_identity: DashMap::new(),
            next_id: AtomicU64::new(1),
            rate_limiter: CreationRateLimiter::new(),
            generic_buckets: ShardedLru::new(cap),
        };
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let addr = IpAddr::V4(Ipv4Addr::new(203, b[1], b[2], b[3]));
            graph.use_generic_bucket(addr, 0.5);
        }
        assert_eq!(
            graph.generic_bucket_count(),
            cap,
            "generic_buckets non bounded realtime (got {})",
            graph.generic_bucket_count()
        );
        // Orphan-free: ogni bucket sfrattato ha rimosso la SUA identità da `identities`
        // → la mappa primaria traccia esattamente i bucket vivi (no leak, no bypass cap).
        assert_eq!(
            graph.identities.len(),
            cap,
            "LEAK di identità orfane: identities.len()={} (atteso == cap {})",
            graph.identities.len(),
            cap
        );
    }

    /// 🚨 LIDENT-IPS (OOM, gemello BG1 sull'inner map delle identità): `LogicalIdentity.ips`
    /// è cappato. Scenario Sybil (proprio quello che il graph rileva): 1 cookie/fingerprint
    /// da milioni di IP → tutti correlati alla STESSA identità → `ips` cresce illimitato.
    /// Le identità sono cappate (MAX_IDENTITIES) ma il loro inner set no. Mutation-verify:
    /// togliendo `self.ips.len() < MAX_IPS_PER_IDENTITY` → ips.len() esplode.
    #[test]
    fn logical_identity_ips_capped_under_ip_flood() {
        let mut identity =
            LogicalIdentity::new(IdentityId(1), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 0, 0, 0, None);
        for i in 0..(MAX_IPS_PER_IDENTITY as u32 + 5000) {
            let b = i.to_be_bytes();
            identity.touch(IpAddr::V4(Ipv4Addr::new(172, b[1], b[2], b[3])));
        }
        assert_eq!(
            identity.ips.len(),
            MAX_IPS_PER_IDENTITY,
            "ips inner map non cappato (got {})",
            identity.ips.len()
        );
    }

    // ─── Test 8: Candidate pre-selection efficiency ──────────────────────

    #[test]
    fn test_candidate_preselection_efficiency() {
        let graph = IdentityGraph::new();

        // Create 100 identities with different signals
        for i in 0u64..100 {
            let test_ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 255) as u8, (i % 255 + 1) as u8));
            let _ = graph.process(
                test_ip,
                &format!("UA-{}", i),
                0x1000 + i,
                0x2000 + i,
                Some(0x3000 + i),
                0.0,
            );
        }

        assert_eq!(graph.tracked_identities(), 100);

        // Now search for a specific fingerprint that only identity #42 has
        let candidates = graph.candidate_ids(
            IdentityGraph::hash_string("UA-42"),
            0x1000 + 42,
            0x2000 + 42,
            Some(0x3000 + 42),
        );

        // Should find exactly 1 candidate (the one matching all signals)
        // (plus possibly others that share individual signal values, which is
        // unlikely given unique values)
        assert!(
            candidates.len() <= 4,
            "Inverse index should return small candidate set, got {}",
            candidates.len()
        );
        assert!(
            !candidates.is_empty(),
            "Should find at least 1 candidate"
        );
    }

    // ─── Test 9: Priority eviction (high risk survives) ──────────────────

    #[test]
    fn test_priority_eviction_high_risk_survives() {
        let graph = IdentityGraph::new();

        // Create an identity with high risk
        let _ = graph.process(ip(1), "high-risk-ua", 0xAAAA, 0xBBBB, Some(0xCCCC), 0.8);

        // Create another identity with low risk
        let _ = graph.process(ip(2), "low-risk-ua", 0xDDDD, 0xEEEE, Some(0xFFFF), 0.01);

        assert_eq!(graph.tracked_identities(), 2);

        // Manually make the low-risk identity stale
        let id2 = IdentityId(2);
        if let Some(mut identity) = graph.identities.get_mut(&id2) {
            // Simulate staleness by backdating last_seen
            identity.last_seen = Instant::now() - Duration::from_secs(7200); // 2 hours ago
        }

        // Also make the high-risk identity stale
        let id1 = IdentityId(1);
        if let Some(mut identity) = graph.identities.get_mut(&id1) {
            identity.last_seen = Instant::now() - Duration::from_secs(7200);
        }

        graph.evict_stale_identities();

        // High-risk identity should survive (priority retention)
        assert!(
            graph.identities.contains_key(&id1),
            "High-risk identity should survive eviction (priority retention)"
        );
        // Low-risk stale identity should be evicted
        assert!(
            !graph.identities.contains_key(&id2),
            "Low-risk stale identity should be evicted"
        );
    }

    // ─── Test 10: Cleanup expired weak links ─────────────────────────────

    #[test]
    fn test_cleanup_expired_weak_links() {
        let graph = IdentityGraph::new();

        // Create two identities
        let _ = graph.process(ip(1), "ua-1", 0xA1, 0xB1, Some(0xC1), 0.0);
        let _ = graph.process(ip(2), "ua-2", 0xA2, 0xB2, Some(0xC2), 0.0);

        let id1 = IdentityId(1);
        let id2 = IdentityId(2);

        // Manually add an expired weak association
        if let Some(mut identity) = graph.identities.get_mut(&id1) {
            identity.weak_associations.push(WeakAssociation {
                target_id: id2,
                similarity: 0.45,
                risk_share: WEAK_RISK_SHARE,
                created_at: Instant::now() - Duration::from_secs(31 * 60), // 31 min ago (expired)
            });
            assert_eq!(identity.weak_associations.len(), 1);
        }

        // Run cleanup
        graph.cleanup();

        // Expired weak association should be removed
        if let Some(identity) = graph.identities.get(&id1) {
            assert!(
                identity.weak_associations.is_empty(),
                "Expired weak association should be removed by cleanup"
            );
        };
    }

    // ─── Test 11: Inverse index cleanup after identity removal ───────────

    #[test]
    fn test_inverse_index_cleanup() {
        let graph = IdentityGraph::new();

        // Create identity
        let _ = graph.process(ip(1), "test-ua", 0xAA, 0xBB, Some(0xCC), 0.0);

        assert!(
            graph.signal_index_size() > 0,
            "Inverse index should have entries"
        );

        // Make it stale
        let id1 = IdentityId(1);
        if let Some(mut identity) = graph.identities.get_mut(&id1) {
            identity.last_seen = Instant::now() - Duration::from_secs(7200);
        }

        // Cleanup should remove the identity and clean the inverse index
        graph.cleanup();

        assert_eq!(
            graph.tracked_identities(),
            0,
            "Stale identity should be removed"
        );
        assert_eq!(
            graph.signal_index_size(),
            0,
            "Inverse index should be cleaned after identity removal"
        );
    }

    // ─── Test 12: Max weak associations enforced ─────────────────────────

    #[test]
    fn test_max_weak_associations_enforced() {
        let graph = IdentityGraph::new();

        // Create an identity
        let _ = graph.process(ip(1), "ua-main", 0xA0, 0xB0, Some(0xC0), 0.0);

        let id1 = IdentityId(1);

        // Manually add MAX_WEAK_ASSOCIATIONS + 2 weak associations
        if let Some(mut identity) = graph.identities.get_mut(&id1) {
            for i in 0..(MAX_WEAK_ASSOCIATIONS + 2) {
                let target = IdentityId(100 + i as u64);
                let sim = 0.40 + (i as f64) * 0.01;
                identity.weak_associations.push(WeakAssociation::new(target, sim));
            }

            // Prune should enforce the max
            identity.prune_weak_associations();

            assert!(
                identity.weak_associations.len() <= MAX_WEAK_ASSOCIATIONS,
                "Should have at most {} weak associations, got {}",
                MAX_WEAK_ASSOCIATIONS,
                identity.weak_associations.len()
            );

            // The remaining associations should be the ones with highest similarity
            for wa in &identity.weak_associations {
                assert!(
                    wa.similarity >= 0.42,
                    "Lowest similarity associations should have been dropped"
                );
            }
        };
    }

    // ─── Test 13: Generic bucket reuse ───────────────────────────────────

    #[test]
    fn test_generic_bucket_reuse() {
        let graph = IdentityGraph::new();

        // Exhaust rate limit for ip(1)
        for i in 0..MAX_NEW_PER_IP_PER_MINUTE {
            let fp = 0x1000 + i;
            let bh = 0x2000 + i;
            let ck = 0x3000 + i;
            let _ = graph.process(ip(1), &format!("UA-{}", i), fp, bh, Some(ck), 0.0);
        }

        let identities_before = graph.tracked_identities();

        // Next two requests should go to same generic bucket
        let r1 = graph.process(ip(1), "over-limit-1", 0xF1, 0xF2, Some(0xF3), 0.1);
        let r2 = graph.process(ip(1), "over-limit-2", 0xF4, 0xF5, Some(0xF6), 0.2);

        assert!(r1.identity_churn_detected);
        assert!(r2.identity_churn_detected);

        // Should have created only 1 generic bucket identity (reused for both)
        assert_eq!(
            graph.tracked_identities(),
            identities_before + 1,
            "Generic bucket should be reused, not create new identities"
        );
    }

    // ─── Test 14: Subnet rate limiting ───────────────────────────────────

    #[test]
    fn test_subnet_rate_limiting() {
        let graph = IdentityGraph::new();

        // Create identities from different IPs in the same /24 subnet
        // MAX_NEW_PER_SUBNET_PER_MINUTE = 100
        for i in 1..=100u8 {
            let subnet_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i));
            let fp = 0x1000 + i as u64;
            let bh = 0x2000 + i as u64;
            let ck = 0x3000 + i as u64;
            let _ = graph.process(subnet_ip, &format!("UA-{}", i), fp, bh, Some(ck), 0.0);
        }

        // Next request from same subnet (different IP that hasn't been rate-limited per-IP)
        // should be rate-limited by the subnet counter
        let overflow_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let result = graph.process(overflow_ip, "UA-overflow", 0xF000, 0xF001, Some(0xF002), 0.0);

        assert!(
            result.identity_churn_detected,
            "Should trigger churn detection when /24 subnet rate limit exceeded"
        );
    }

    // ─── Test 15: Risk accumulation across merged requests ───────────────

    #[test]
    fn test_risk_accumulation_across_merges() {
        let graph = IdentityGraph::new();

        // First request establishes identity with some risk
        let r1 = graph.process(ip(1), "ua", 0xAA, 0xBB, Some(0xCC), 0.3);

        // Second request merges (same signals, different IP) and adds more risk
        // HTTP(0.25) + UA(0.15) + Behavior(0.20) + Cookie(0.30) = 0.90 >= 0.55
        let r2 = graph.process(ip(2), "ua", 0xAA, 0xBB, Some(0xCC), 0.4);

        assert!(
            r2.effective_risk > r1.effective_risk,
            "Risk should accumulate: {} > {}",
            r2.effective_risk,
            r1.effective_risk
        );

        // Verify the identity has both IPs
        let id = IdentityId(1);
        if let Some(identity) = graph.identities.get(&id) {
            assert!(identity.ips.contains_key(&ip(1)));
            assert!(identity.ips.contains_key(&ip(2)));
            assert_eq!(identity.ips.len(), 2, "Should have 2 associated IPs");
        };
    }
}
