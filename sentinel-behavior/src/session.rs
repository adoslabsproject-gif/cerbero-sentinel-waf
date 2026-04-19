//! Session Analysis
//!
//! Analyzes session behavior for suspicious patterns:
//! - Session hijacking detection
//! - Cookie manipulation
//! - Fingerprint changes

use sentinel_core::{BehaviorConfig, Request, SentinelError};
use dashmap::DashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
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
    #[allow(dead_code)]
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
    /// Session fingerprints by session ID
    sessions: Arc<DashMap<String, SessionFingerprint>>,
    /// Configuration
    config: BehaviorConfig,
    /// Maximum session age
    max_age: Duration,
}

impl SessionAnalyzer {
    /// Create new session analyzer
    pub fn new(config: &BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            sessions: Arc::new(DashMap::new()),
            config: config.clone(),
            max_age: Duration::from_secs(config.session_max_age_secs),
        })
    }

    /// Analyze session risk
    pub async fn analyze(&self, request: &Request) -> Result<SessionRisk, SentinelError> {
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

        // Check if session exists
        if let Some(existing) = self.sessions.get(&session_id) {
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

        self.sessions
            .entry(session_id)
            .and_modify(|existing| {
                existing.last_seen = Instant::now();
                existing.request_count += 1;
            })
            .or_insert(fingerprint);
    }

    /// Extract session ID from request
    fn extract_session_id(&self, request: &Request) -> Option<String> {
        // Check Authorization header (JWT)
        if let Some(auth) = request.headers.get("authorization") {
            if auth.starts_with("Bearer ") {
                // Hash the JWT to use as session ID
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
                    return Some(format!("cookie:{}", &part[part.find('=').unwrap() + 1..]));
                }
            }
        }

        // Check X-Session-ID header
        if let Some(sid) = request.headers.get("x-session-id") {
            return Some(format!("header:{}", sid));
        }

        None
    }

    /// Cleanup expired sessions
    pub async fn cleanup(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.last_seen) < self.max_age
        });
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
}
