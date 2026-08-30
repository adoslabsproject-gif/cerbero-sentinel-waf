//! F11 (2026-06-02): rate limiter per-endpoint configurabile.
//!
//! Layer 1.7 — fra CRS patterns (1.5) e fingerprint (3). Rate limit
//! granulare per (method + path pattern), sliding window, bypass per
//! IP whitelist + bot allowlist verified.
//!
//! Configurazione via TOML (default policy + override per pattern).
//! Hot-reload via env `SENTINEL_RATE_LIMITS_PATH` (file watch notify).
//!
//! Esempi rule predefinite (in DEFAULT_POLICIES sotto):
//!   - POST /login            → 5 req / 60s per IP
//!   - POST /signup           → 3 req / 60s per IP
//!   - POST /api/v1/admin/*   → 30 req / 60s per IP (operazioni admin)
//!   - GET /api/v1/*          → 120 req / 60s per IP (API client medi)
//!   - default                → 600 req / 60s per IP (browsing umano)
//!
//! Response: edge_score += 0.85 (>= STRONG threshold) → ban + 429 downstream.

use once_cell::sync::Lazy;
use sentinel_core::sharded_lru::ShardedLru;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Una policy di rate limit per un pattern endpoint.
#[derive(Debug, Clone)]
pub struct EndpointPolicy {
    /// Method HTTP ("*" = any). Case-insensitive.
    pub method: &'static str,
    /// Path pattern semplice (prefix match con `*` wildcard finale).
    /// Es: "/api/v1/admin/*", "/login", "/api/*".
    pub path_pattern: &'static str,
    /// Numero massimo richieste per finestra.
    pub max_requests: u32,
    /// Finestra in secondi.
    pub window_secs: u64,
    /// Human label per logging + dashboard.
    pub label: &'static str,
}

/// Default policy ordinate per priorita\` (specifiche prima del wildcard).
/// First-match wins.
pub const DEFAULT_POLICIES: &[EndpointPolicy] = &[
    EndpointPolicy {
        method: "POST",
        path_pattern: "/login",
        max_requests: 5,
        window_secs: 60,
        label: "login-strict",
    },
    EndpointPolicy {
        method: "POST",
        path_pattern: "/signup",
        max_requests: 3,
        window_secs: 60,
        label: "signup-strict",
    },
    EndpointPolicy {
        method: "POST",
        path_pattern: "/2fa/*",
        max_requests: 10,
        window_secs: 60,
        label: "2fa-strict",
    },
    EndpointPolicy {
        method: "POST",
        path_pattern: "/api/v1/auth/*",
        max_requests: 10,
        window_secs: 60,
        label: "auth-strict",
    },
    EndpointPolicy {
        method: "*",
        path_pattern: "/api/v1/admin/*",
        max_requests: 30,
        window_secs: 60,
        label: "admin-medium",
    },
    EndpointPolicy {
        method: "POST",
        path_pattern: "/api/v1/workspaces",
        max_requests: 10,
        window_secs: 60,
        label: "workspace-create-medium",
    },
    EndpointPolicy {
        method: "*",
        path_pattern: "/api/v1/*",
        max_requests: 120,
        window_secs: 60,
        label: "api-default",
    },
    EndpointPolicy {
        method: "*",
        path_pattern: "/*",
        max_requests: 600,
        window_secs: 60,
        label: "browsing-default",
    },
];

/// Risultato di una check rate limit.
#[derive(Debug, Clone)]
pub struct LimitDecision {
    pub limited: bool,
    pub policy_label: &'static str,
    pub current_count: u32,
    pub max_requests: u32,
    pub window_secs: u64,
    pub retry_after_secs: u64,
}

/// Sliding-window state per (IP+policy).
#[derive(Default)]
struct WindowState {
    hits: VecDeque<Instant>,
}

/// Cap HARD sul numero di coppie (ip, policy) tracciate. Anti-DoS (EL1-A): bound della
/// memoria SELF-CONTAINED in tempo reale via `ShardedLru` (evict LRU O(1) all'inserimento,
/// non più delegato solo alla cleanup esterna EL2 né a un batch-sort O(n) sull'hot-path).
const DEFAULT_MAX_ENTRIES: usize = 200_000;

/// Engine rate limit per-endpoint.
pub struct EndpointLimiter {
    policies: Vec<EndpointPolicy>,
    /// Stato per (IP, policy). `ShardedLru` → bound HARD in tempo reale: quando lo
    /// shard è pieno, l'inserimento di una key nuova evicta la LRU in O(1) (classe
    /// EL1/DD1 — niente batch-sort O(n) sull'hot-path).
    state: ShardedLru<(IpAddr, &'static str), WindowState>,
}

impl EndpointLimiter {
    pub fn new(policies: Vec<EndpointPolicy>) -> Self {
        Self {
            policies,
            state: ShardedLru::new(DEFAULT_MAX_ENTRIES),
        }
    }

    /// Default constructor con policy predefinite.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_POLICIES.to_vec())
    }

    /// Builder: override del cap hard sulle entry (anti-DoS, EL1-A).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.state = ShardedLru::new(max_entries.max(1));
        self
    }

    /// Match policy per (method, path). First-match wins (DEFAULT_POLICIES sono ordinate).
    pub fn match_policy(&self, method: &str, path: &str) -> Option<&EndpointPolicy> {
        self.policies.iter().find(|p| {
            (p.method == "*" || p.method.eq_ignore_ascii_case(method))
                && path_matches(p.path_pattern, path)
        })
    }

    /// Check rate limit per (ip, method, path). Side-effect: incrementa counter.
    /// Ritorna decisione + label policy per logging.
    pub fn check(&self, ip: IpAddr, method: &str, path: &str) -> LimitDecision {
        let policy = match self.match_policy(method, path) {
            Some(p) => p,
            None => {
                // Nessun match → no limit (paranoia: in DEFAULT c'e\` sempre `/*`)
                return LimitDecision {
                    limited: false,
                    policy_label: "no-policy",
                    current_count: 0,
                    max_requests: u32::MAX,
                    window_secs: 0,
                    retry_after_secs: 0,
                };
            }
        };

        let now = Instant::now();
        let window = Duration::from_secs(policy.window_secs);
        let key = (ip, policy.label);
        // EL1-B (DoS): il deque NON deve crescere col RATE dell'attacco. Cap a
        // max_requests+1 → basta per sapere "sei oltre" e calcolare retry_after dalla front.
        let cap = policy.max_requests as usize + 1;

        // EL1-A: bound HARD della mappa in tempo reale. `with_entry_mut` fa get-or-create
        // per (ip, policy) e — se lo shard è pieno — evicta la LRU in O(1) PRIMA di
        // inserire (niente batch-sort O(n) sull'hot-path, classe EL1/DD1 chiusa).
        // Evictare un IP ruotato è innocuo per il limiting (riparte da zero); qui si
        // bounda solo la RAM.
        // Tutto sotto UN solo lock dello shard (no doppio-lock, no race su retry_after).
        let (count, retry_after_secs) = self.state.with_entry_mut(
            key,
            WindowState::default,
            |state| {
                // Sliding window: cleanup expired
                while let Some(t) = state.hits.front() {
                    if now.duration_since(*t) > window {
                        state.hits.pop_front();
                    } else {
                        break;
                    }
                }
                // Oltre il cap NON si accoda (prima cresceva all'infinito anche su richieste
                // già `limited`, e un singolo IP poteva OOM-are il WAF floddando).
                if state.hits.len() < cap {
                    state.hits.push_back(now);
                }
                let count = state.hits.len() as u32;
                let retry = if count > policy.max_requests {
                    // Retry-After = secondi alla prima entry (la più vecchia non-scaduta) per scadere.
                    state
                        .hits
                        .front()
                        .map(|t| {
                            let elapsed = now.duration_since(*t);
                            window.saturating_sub(elapsed).as_secs().max(1)
                        })
                        .unwrap_or(policy.window_secs)
                } else {
                    0
                };
                (count, retry)
            },
        );
        let limited = count > policy.max_requests;

        LimitDecision {
            limited,
            policy_label: policy.label,
            current_count: count,
            max_requests: policy.max_requests,
            window_secs: policy.window_secs,
            retry_after_secs,
        }
    }

    /// Cleanup stale entries (chiamato periodicamente da sentinel-server).
    pub fn cleanup_expired(&self, now: Instant) {
        let max_window = self
            .policies
            .iter()
            .map(|p| p.window_secs)
            .max()
            .unwrap_or(60);
        let cutoff = Duration::from_secs(max_window + 60);
        self.state.retain(|_, state| {
            while let Some(t) = state.hits.front() {
                if now.duration_since(*t) > cutoff {
                    state.hits.pop_front();
                } else {
                    break;
                }
            }
            !state.hits.is_empty()
        });
    }

    /// Metrics: numero (ip, policy) tracciati attualmente.
    pub fn tracked_count(&self) -> usize {
        self.state.len()
    }
}

/// Normalizza un path per il MATCHING delle policy: percent-decode iterativo (`/%6cogin`),
/// lowercase ASCII (`/Login`) e rimozione del trailing slash (`/login/`), eccetto la root.
/// Senza, queste varianti aggirano una policy STRETTA (es. login 5/min) scivolando nel
/// catch-all permissivo `/*` (600/min) → brute-force.
fn normalize_match_path(p: &str) -> String {
    let decoded = sentinel_core::percent_decode_iterative(p, 3);
    let lower = decoded.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Path pattern match con `*` wildcard SOLO finale, su path NORMALIZZATO (anti-bypass
/// case/slash/encoding). Es: pattern `/api/v1/*` matcha `/api/v1/users`, `/api/v1/x/y`,
/// NON `/api/v2`. Pattern senza `*` → exact match (post-normalizzazione).
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/*" {
        return true;
    }
    let np = normalize_match_path(path);
    let path = np.as_str();
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let nprefix = normalize_match_path(prefix);
        let prefix = nprefix.as_str();
        path.starts_with(prefix)
            && (path.len() == prefix.len() || path.as_bytes()[prefix.len()] == b'/')
    } else {
        normalize_match_path(pattern) == path
    }
}

/// Singleton globale (init lazy via `Arc<EndpointLimiter>`).
pub static GLOBAL_ENDPOINT_LIMITER: Lazy<Arc<EndpointLimiter>> =
    Lazy::new(|| Arc::new(EndpointLimiter::with_defaults()));

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(o: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, o))
    }

    #[test]
    fn path_matches_exact() {
        assert!(path_matches("/login", "/login"));
        assert!(!path_matches("/login", "/login/extra"));
        assert!(!path_matches("/login", "/loginx"));
    }

    #[test]
    fn path_matches_wildcard_suffix() {
        assert!(path_matches("/api/v1/*", "/api/v1/users"));
        assert!(path_matches("/api/v1/*", "/api/v1/users/123"));
        assert!(path_matches("/api/v1/*", "/api/v1"));
        assert!(!path_matches("/api/v1/*", "/api/v2/users"));
    }

    #[test]
    fn path_matches_catchall() {
        assert!(path_matches("/*", "/anything"));
        assert!(path_matches("/*", "/"));
    }

    #[test]
    fn match_policy_selects_login_strict() {
        let l = EndpointLimiter::with_defaults();
        let p = l.match_policy("POST", "/login").expect("must match");
        assert_eq!(p.label, "login-strict");
        assert_eq!(p.max_requests, 5);
    }

    // ── ANTI-BYPASS: case / trailing-slash / percent-encoding non aggirano la policy ──
    #[test]
    fn path_matches_is_case_insensitive() {
        assert!(path_matches("/login", "/Login"));
        assert!(path_matches("/login", "/LOGIN"));
        assert!(path_matches("/api/v1/*", "/API/V1/users"));
    }

    #[test]
    fn path_matches_ignores_trailing_slash() {
        assert!(path_matches("/login", "/login/"));
        assert!(path_matches("/login", "/login///"));
        // ma NON deve matchare un sub-path: /login/extra resta diverso da /login
        assert!(!path_matches("/login", "/login/extra"));
    }

    #[test]
    fn path_matches_decodes_percent_encoding() {
        // /%6cogin → /login ; doppio-encoding /%256cogin → /%6cogin → /login
        assert!(path_matches("/login", "/%6cogin"));
        assert!(path_matches("/login", "/%256cogin"));
        assert!(path_matches("/login", "/%4cOGIN")); // encoding + case combinati
    }

    #[test]
    fn match_policy_login_strict_not_bypassable_by_variants() {
        let l = EndpointLimiter::with_defaults();
        // MUTATION-VERIFY del fix: pre-normalizzazione queste cadevano nel catch-all
        // (login-default 600/min); ora devono colpire login-strict (5/min).
        for variant in ["/Login", "/login/", "/LOGIN/", "/%6cogin"] {
            let p = l
                .match_policy("POST", variant)
                .unwrap_or_else(|| panic!("nessuna policy per {variant}"));
            assert_eq!(p.label, "login-strict", "variant {variant} deve colpire login-strict");
            assert_eq!(p.max_requests, 5, "variant {variant} deve avere il cap stretto");
        }
    }

    #[test]
    fn match_policy_signup_strict() {
        let l = EndpointLimiter::with_defaults();
        let p = l.match_policy("POST", "/signup").expect("signup");
        assert_eq!(p.label, "signup-strict");
        assert_eq!(p.max_requests, 3);
    }

    #[test]
    fn match_policy_admin_medium() {
        let l = EndpointLimiter::with_defaults();
        let p = l.match_policy("GET", "/api/v1/admin/users").expect("admin");
        assert_eq!(p.label, "admin-medium");
    }

    #[test]
    fn match_policy_api_default() {
        let l = EndpointLimiter::with_defaults();
        let p = l.match_policy("GET", "/api/v1/workflows").expect("api");
        assert_eq!(p.label, "api-default");
        assert_eq!(p.max_requests, 120);
    }

    #[test]
    fn match_policy_browsing_fallback() {
        let l = EndpointLimiter::with_defaults();
        let p = l.match_policy("GET", "/about").expect("browsing fallback");
        assert_eq!(p.label, "browsing-default");
        assert_eq!(p.max_requests, 600);
    }

    #[test]
    fn check_under_threshold_no_limit() {
        let l = EndpointLimiter::with_defaults();
        // 4 POST /login → sotto soglia 5
        for _ in 0..4 {
            let d = l.check(ip(1), "POST", "/login");
            assert!(!d.limited);
        }
    }

    #[test]
    fn check_at_threshold_5th_login_still_allowed() {
        let l = EndpointLimiter::with_defaults();
        for _ in 0..5 {
            let d = l.check(ip(2), "POST", "/login");
            assert!(!d.limited, "fino al 5 deve passare");
        }
    }

    #[test]
    fn check_over_threshold_login_is_limited() {
        let l = EndpointLimiter::with_defaults();
        for _ in 0..5 {
            l.check(ip(3), "POST", "/login");
        }
        let d6 = l.check(ip(3), "POST", "/login");
        assert!(d6.limited, "6esimo POST /login deve essere limitato");
        assert_eq!(d6.policy_label, "login-strict");
        assert!(d6.retry_after_secs > 0);
        assert!(d6.retry_after_secs <= 60);
    }

    #[test]
    fn check_signup_limit_at_3() {
        let l = EndpointLimiter::with_defaults();
        for _ in 0..3 {
            l.check(ip(4), "POST", "/signup");
        }
        let d4 = l.check(ip(4), "POST", "/signup");
        assert!(d4.limited);
        assert_eq!(d4.policy_label, "signup-strict");
    }

    #[test]
    fn check_independent_per_ip() {
        let l = EndpointLimiter::with_defaults();
        for _ in 0..6 {
            l.check(ip(10), "POST", "/login"); // saturating ip 10
        }
        // IP diverso parte da 0
        let d = l.check(ip(11), "POST", "/login");
        assert!(!d.limited);
    }

    #[test]
    fn check_independent_per_endpoint_for_same_ip() {
        let l = EndpointLimiter::with_defaults();
        for _ in 0..6 {
            l.check(ip(20), "POST", "/login");
        }
        // Stesso IP su path diverso → policy diversa → counter separato
        let d = l.check(ip(20), "POST", "/signup");
        assert!(!d.limited, "policy signup deve avere counter separato");
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let l = EndpointLimiter::with_defaults();
        l.check(ip(30), "POST", "/login");
        assert!(l.tracked_count() >= 1);
        let future = Instant::now() + Duration::from_secs(60 * 60 * 2); // 2h
        l.cleanup_expired(future);
        assert_eq!(l.tracked_count(), 0);
    }

    #[test]
    fn method_wildcard_admin_matches_get_post_delete() {
        let l = EndpointLimiter::with_defaults();
        for method in &["GET", "POST", "DELETE", "PATCH"] {
            let p = l.match_policy(method, "/api/v1/admin/users").expect(method);
            assert_eq!(p.label, "admin-medium", "method {} on admin path must match wildcard", method);
        }
    }

    #[test]
    fn case_insensitive_method() {
        let l = EndpointLimiter::with_defaults();
        let p_lower = l.match_policy("post", "/login").expect("lower");
        let p_upper = l.match_policy("POST", "/login").expect("upper");
        let p_mixed = l.match_policy("Post", "/login").expect("mixed");
        assert_eq!(p_lower.label, p_upper.label);
        assert_eq!(p_lower.label, p_mixed.label);
    }

    #[test]
    fn retry_after_decreases_as_window_progresses() {
        // Test conceptual: il primo hit nella finestra determina retry_after,
        // ogni nuovo hit non resetta il timer della prima entry.
        let l = EndpointLimiter::with_defaults();
        for _ in 0..5 {
            l.check(ip(40), "POST", "/login");
        }
        let d1 = l.check(ip(40), "POST", "/login");
        assert!(d1.limited);
        let d2 = l.check(ip(40), "POST", "/login");
        // Il secondo hit limitato dovrebbe avere retry <= del primo (window non resetta)
        assert!(d2.retry_after_secs <= d1.retry_after_secs);
    }

    /// 🚨 EL1-B (DoS): il deque NON deve crescere col RATE dell'attacco. Un singolo IP
    /// che floda /login (max 5) ignorando i 429 non deve accumulare timestamp illimitati:
    /// il count resta cappato a max+1 (6), non cresce con N. Pre-fix: count == N (OOM).
    #[test]
    fn el1b_deque_bounded_under_flood_single_ip() {
        let l = EndpointLimiter::with_defaults();
        let mut last = l.check(ip(50), "POST", "/login");
        for _ in 0..10_000 {
            last = l.check(ip(50), "POST", "/login");
        }
        assert!(last.limited, "sotto flood deve restare limited");
        // login-strict max=5 → deque cappato a 6, NON a 10_001.
        assert!(
            last.current_count <= 6,
            "EL1-B: il deque cresce col rate dell'attacco (count={}, atteso <=6)",
            last.current_count
        );
        // E continua a limitare correttamente (retry_after sensato).
        assert!(last.retry_after_secs > 0 && last.retry_after_secs <= 60);
    }

    /// 🚨 EL1-A (DoS): la mappa `state` è bounded sotto IP-rotation in TEMPO REALE
    /// (ShardedLru evict-LRU O(1) all'inserimento), SELF-CONTAINED senza cleanup_expired
    /// esterna. Pre-fix: nessun cap → crescita illimitata.
    #[test]
    fn el1a_state_map_bounded_under_ip_rotation() {
        use std::net::Ipv6Addr;
        // cap multiplo del numero di shard → capacity() == cap esatta. Con 2000 IP
        // distinti su 64 slot ogni shard satura (pigeonhole) → la mappa è PIENA.
        let cap = 64;
        let l = EndpointLimiter::with_defaults().with_max_entries(cap);
        for i in 0..2000u16 {
            let attacker = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i));
            l.check(attacker, "POST", "/login");
        }
        // == cap (non solo <=): uccide SIA la mutazione "unbounded" (>cap) SIA la
        // false-green "non-inserisce-mai" (tracked_count()==0 <= cap passerebbe).
        assert_eq!(
            l.tracked_count(),
            cap,
            "EL1-A: la mappa state deve essere bounded ED esattamente piena a cap={cap} \
             (got {})",
            l.tracked_count()
        );
    }
}
