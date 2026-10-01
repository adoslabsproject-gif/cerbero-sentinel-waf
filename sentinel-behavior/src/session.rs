//! Session Analysis
//!
//! Analyzes session behavior for suspicious patterns:
//! - Session hijacking detection
//! - Cookie manipulation
//! - Fingerprint changes

use sentinel_core::sharded_lru::ShardedLru;
use sentinel_core::{BehaviorConfig, Request, SentinelError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Session risk assessment
#[derive(Debug, Clone)]
pub struct SessionRisk {
    /// Risk score (0.0 - 1.0)
    pub score: f64,
    /// Whether session is suspicious
    pub is_suspicious: bool,
    /// Reason for suspicion
    pub reason: Option<String>,
}

/// Session fingerprint
#[derive(Debug, Clone)]
struct SessionFingerprint {
    /// IP address
    ip: IpAddr,
    /// User agent hash
    ua_hash: u64,
    /// Accept-Language hash
    lang_hash: u64,
    /// First seen
    first_seen: Instant,
    /// Last seen
    last_seen: Instant,
    /// Request count
    request_count: u64,
}

impl SessionFingerprint {
    fn from_request(request: &Request) -> Self {
        let ua = request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        let lang = request.headers.get("accept-language").map(|s| s.as_str()).unwrap_or("");

        Self {
            ip: request.client_ip,
            ua_hash: Self::hash_string(ua),
            lang_hash: Self::hash_string(lang),
            first_seen: Instant::now(),
            last_seen: Instant::now(),
            request_count: 1,
        }
    }

    fn hash_string(s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    fn matches(&self, other: &SessionFingerprint) -> f64 {
        let mut score = 0.0;
        let mut weight = 0.0;

        // IP match (most important)
        if self.ip == other.ip {
            score += 0.5;
        }
        weight += 0.5;

        // UA match
        if self.ua_hash == other.ua_hash {
            score += 0.3;
        }
        weight += 0.3;

        // Language match
        if self.lang_hash == other.lang_hash {
            score += 0.2;
        }
        weight += 0.2;

        score / weight
    }
}

/// Session analyzer
pub struct SessionAnalyzer {
    /// Session fingerprints by session ID. SESSION1 (anti-OOM/CPU-DoS): la chiave
    /// è client-controlled → senza bound un attaccante riempie la mappa all'OOM.
    /// `ShardedLru` la cappa con eviction LRU true-O(1) (no scan O(n) per-request,
    /// classe DD1) e concorrenza sharded (no lock globale). Vedi sentinel-core.
    sessions: ShardedLru<String, SessionFingerprint>,
    /// Configuration
    config: BehaviorConfig,
    /// Maximum session age
    max_age: Duration,
}

impl SessionAnalyzer {
    /// Create new session analyzer
    pub fn new(config: &BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            sessions: ShardedLru::new(config.session_max_entries.max(1)),
            config: config.clone(),
            max_age: Duration::from_secs(config.session_max_age_secs),
        })
    }

    /// Analyze session risk
    pub async fn analyze(&self, request: &Request) -> Result<SessionRisk, SentinelError> {
        // Check if honeypot was triggered for this IP (server-computed, passed via header)
        let honeypot_triggered = request.headers
            .get("x-honeypot-triggered")
            .map(|v| v == "true")
            .unwrap_or(false);

        if honeypot_triggered {
            return Ok(SessionRisk {
                score: 0.8,
                is_suspicious: true,
                reason: Some("IP has honeypot history (server-verified)".to_string()),
            });
        }

        let session_id = self.extract_session_id(request);

        let Some(session_id) = session_id else {
            // No session - low risk for anonymous requests
            return Ok(SessionRisk {
                score: 0.0,
                is_suspicious: false,
                reason: None,
            });
        };

        let current_fingerprint = SessionFingerprint::from_request(request);

        // Check if session exists (peek: NO promote — la recency la guida record()).
        let existing = self.sessions.with_peek(&session_id, |e| e.cloned());
        if let Some(existing) = existing {
            let match_score = existing.matches(&current_fingerprint);

            // Check for fingerprint change (potential hijacking)
            if match_score < self.config.fingerprint_match_threshold {
                // Fingerprint changed significantly
                let mut reasons = Vec::new();

                if existing.ip != current_fingerprint.ip {
                    reasons.push("IP changed");
                }
                if existing.ua_hash != current_fingerprint.ua_hash {
                    reasons.push("User-Agent changed");
                }

                return Ok(SessionRisk {
                    score: 1.0 - match_score,
                    is_suspicious: true,
                    reason: Some(reasons.join(", ")),
                });
            }

            // Check for impossible travel (IP change too fast)
            let time_since_last = Instant::now().duration_since(existing.last_seen);
            if existing.ip != current_fingerprint.ip && time_since_last < Duration::from_secs(60) {
                return Ok(SessionRisk {
                    score: 0.8,
                    is_suspicious: true,
                    reason: Some("Impossible travel: IP changed in < 60s".to_string()),
                });
            }
        }

        Ok(SessionRisk {
            score: 0.0,
            is_suspicious: false,
            reason: None,
        })
    }

    /// Record a request
    pub async fn record(&self, request: &Request) {
        let session_id = self.extract_session_id(request);

        let Some(session_id) = session_id else {
            return;
        };

        let fingerprint = SessionFingerprint::from_request(request);

        // SESSION1: upsert true-O(1). Se la key è NUOVA e lo shard è al cap, lo
        // ShardedLru evicta la LRU in O(1) (niente scan O(n) per-request, classe
        // DD1). Le key esistenti fanno solo update + promote della recency.
        self.sessions.upsert(
            session_id,
            || fingerprint,
            |existing| {
                existing.last_seen = Instant::now();
                existing.request_count += 1;
            },
        );
    }

    /// Extract session ID from request
    fn extract_session_id(&self, request: &Request) -> Option<String> {
        // Check Authorization header (JWT)
        if let Some(auth) = request.headers.get("authorization") {
            if auth.starts_with("Bearer ") {
                // Hash the JWT to use as session ID.
                // SAFE-SLICE: guardato da starts_with("Bearer ") = 7 byte ASCII → garantisce
                // sia len ≥ 7 (no out-of-range) sia che il byte 7 è un char-boundary (i primi
                // 7 byte sono ASCII) → `&auth[7..]` non può panicare. (FP class non applicabile.)
                let token = &auth[7..];
                let mut hasher = DefaultHasher::new();
                token.hash(&mut hasher);
                return Some(format!("jwt:{}", hasher.finish()));
            }
        }

        // Check Cookie header
        if let Some(cookie) = request.headers.get("cookie") {
            // Look for session cookie
            for part in cookie.split(';') {
                let part = part.trim();
                if part.starts_with("session=") || part.starts_with("sid=") {
                    // split_once: panic-free (niente .unwrap() su find né slice manuale).
                    if let Some((_, val)) = part.split_once('=') {
                        return Some(format!("cookie:{val}"));
                    }
                }
            }
        }

        // Check X-Session-ID header
        if let Some(sid) = request.headers.get("x-session-id") {
            return Some(format!("header:{}", sid));
        }

        None
    }

    /// Drop expired sessions, returning how many were removed.
    ///
    /// Sync, not async: the body is a single `retain` with nothing to await, and the
    /// aggregated `BehavioralAnalysis::cleanup` that now calls it is sync. Until
    /// 2026-10-01 nothing called this at all, so the session map grew for the life
    /// of the process.
    pub fn cleanup(&self) -> usize {
        let before = self.sessions.len();
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.last_seen) < self.max_age
                && now.duration_since(session.first_seen) < self.max_age
        });
        before - self.sessions.len()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_analyzer() -> SessionAnalyzer {
        let config = BehaviorConfig::default();
        SessionAnalyzer::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_no_session() {
        let analyzer = create_analyzer();
        let request = Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };

        let risk = analyzer.analyze(&request).await.unwrap();
        assert!(!risk.is_suspicious);
    }

    #[tokio::test]
    async fn test_consistent_session() {
        let analyzer = create_analyzer();

        let mut headers = std::collections::HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("user-agent".to_string(), "TestAgent/1.0".to_string());

        let request = Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            headers: headers.clone(),
            ..Default::default()
        };

        // First request
        analyzer.record(&request).await;

        // Same session, same fingerprint
        let risk = analyzer.analyze(&request).await.unwrap();
        assert!(!risk.is_suspicious);
    }

    #[tokio::test]
    async fn test_session_ip_change() {
        let analyzer = create_analyzer();

        let mut headers = std::collections::HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("user-agent".to_string(), "TestAgent/1.0".to_string());

        let request1 = Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            headers: headers.clone(),
            ..Default::default()
        };

        // First request
        analyzer.record(&request1).await;

        // Same session, different IP
        let request2 = Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            headers,
            ..Default::default()
        };

        let risk = analyzer.analyze(&request2).await.unwrap();
        assert!(risk.is_suspicious);
        assert!(risk.reason.is_some());
    }

    // ── SESSION1: bounding anti-OOM DoS (mappa illimitata, chiave client-string) ──

    fn create_analyzer_with_cap(cap: usize) -> SessionAnalyzer {
        let config = BehaviorConfig { session_max_entries: cap, ..Default::default() };
        SessionAnalyzer::new(&config).unwrap()
    }

    fn request_with_session(sid: &str) -> Request {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-session-id".to_string(), sid.to_string());
        headers.insert("user-agent".to_string(), "TestAgent/1.0".to_string());
        Request {
            path: "/api/posts".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            headers,
            ..Default::default()
        }
    }

    /// 🚨 BUG-BOUNTY SESSION1: un flood di session id distinti NON deve far
    /// crescere la mappa oltre il cap (senza fix sarebbero 10_000 entry → OOM).
    #[tokio::test]
    async fn test_session_map_bounded_under_id_flood() {
        let analyzer = create_analyzer_with_cap(100);
        for i in 0..10_000 {
            analyzer.record(&request_with_session(&format!("flood-{i}"))).await;
        }
        assert!(
            analyzer.session_count() <= analyzer.sessions.capacity(),
            "mappa non bounded: count={} cap={}",
            analyzer.session_count(),
            analyzer.sessions.capacity()
        );
        assert!(analyzer.session_count() <= 100);
    }

    /// Update di una sessione ESISTENTE non fa crescere la mappa né evicta.
    #[tokio::test]
    async fn test_existing_session_updates_do_not_grow() {
        let analyzer = create_analyzer_with_cap(3);
        for _ in 0..50 {
            analyzer.record(&request_with_session("same")).await;
        }
        assert_eq!(analyzer.session_count(), 1);
    }

    /// La semantica LRU true-O(1) (recency + eviction dell'oldest, O(1)) è
    /// testata in modo deterministico nel primitivo `ShardedLru`
    /// (single_shard_is_true_lru_recency). A livello session verifichiamo
    /// l'INVARIANTE che conta: sotto churn continuo la mappa resta SEMPRE
    /// bounded ad ogni step (mai overflow transitorio = niente CPU/OOM-DoS).
    #[tokio::test]
    async fn test_bounded_under_continuous_churn() {
        let analyzer = create_analyzer_with_cap(160); // capacity = 16 * (160/16) = 160
        let cap = analyzer.sessions.capacity();
        for i in 0..5_000 {
            analyzer.record(&request_with_session(&format!("c-{i}"))).await;
            assert!(
                analyzer.session_count() <= cap,
                "overflow a i={i}: count={}",
                analyzer.session_count()
            );
        }
        assert!(analyzer.session_count() > 0, "non deve svuotarsi");
    }
}
