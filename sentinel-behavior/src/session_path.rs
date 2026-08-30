//! Session Path Behavior Modeling (WI-13)
//!
//! Analyzes navigation sequences per IP to distinguish humans from bots:
//!
//! Humans:  homepage → login → dashboard → /api/orders → /api/orders/123 → logout
//! Bots:    /api/login → /api/login → /api/login → /api/login → /api/login
//! Scanner: /admin → /.env → /wp-login → /phpmyadmin → /actuator → /.git/config
//!
//! Four detection signals:
//! 1. Path repetition: same path > 5 times consecutively → +15 pts
//! 2. Scanner sequence: > 3 scanner paths → +25 pts
//! 3. API-only: > 10 consecutive API requests without HTML → +10 pts
//! 4. Path diversity anomaly: < 3 unique paths in > 20 requests → +10 pts

use sentinel_core::sharded_lru::ShardedLru;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_RECENT_PATHS: usize = 20;
/// Cap HARD del set `unique_paths` (anti-OOM, classe BG1/SP1): il path è
/// attacker-controlled → senza cap un flood di path sempre diversi gonfia il set. La
/// detection scanner scatta a soglie ≪ questo valore.
const MAX_UNIQUE_PATHS: usize = 512;
const MAX_TRACKED_IPS: usize = 20_000;
const EVICTION_IDLE: Duration = Duration::from_secs(1800); // 30 min

/// Known scanner/probe paths
const SCANNER_PATHS: &[&str] = &[
    "/.env", "/.git/config", "/.git/head",
    "/wp-login.php", "/wp-admin", "/xmlrpc.php",
    "/phpmyadmin", "/pma", "/adminer",
    "/actuator", "/actuator/health", "/actuator/env",
    "/debug", "/trace", "/metrics",
    "/admin", "/administrator", "/manager",
    "/backup", "/db", "/database",
    "/console", "/shell", "/cmd",
    "/swagger", "/openapi",
    "/solr", "/elasticsearch", "/_cat",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/server-status", "/server-info",
    "/.well-known/security.txt",
    "/cgi-bin/", "/scripts/",
    "/wp-content/", "/wp-includes/",
];

/// Path entry in the circular buffer
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PathEntry {
    /// Normalized path (e.g., /api/orders/123 → /api/orders/*)
    path: String,
    /// HTTP method
    method: String,
    /// Timestamp
    timestamp: Instant,
}

/// Per-IP session path profile
struct SessionPathProfile {
    /// Recent paths (circular buffer)
    recent_paths: VecDeque<PathEntry>,
    /// Unique paths seen
    unique_paths: HashSet<String>,
    /// Consecutive same-path count
    consecutive_same: u32,
    /// Last path for consecutive tracking
    last_path: Option<String>,
    /// Scanner paths hit
    scanner_paths_hit: u32,
    /// API-only consecutive count
    api_only_count: u32,
    /// Total requests
    total_requests: u32,
    // (rimosso first_request: campo dead_code mai letto)
    /// Last request time
    last_request: Instant,
}

impl SessionPathProfile {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            recent_paths: VecDeque::with_capacity(MAX_RECENT_PATHS),
            unique_paths: HashSet::new(),
            consecutive_same: 0,
            last_path: None,
            scanner_paths_hit: 0,
            api_only_count: 0,
            total_requests: 0,
            last_request: now,
        }
    }

    fn record(&mut self, path: &str, method: &str) {
        let now = Instant::now();
        let normalized = normalize_path(path);

        self.total_requests += 1;
        self.last_request = now;
        // Cap HARD (SP1): non si tracciano nuovi path distinti oltre il cap.
        if self.unique_paths.contains(&normalized) || self.unique_paths.len() < MAX_UNIQUE_PATHS {
            self.unique_paths.insert(normalized.clone());
        }

        // Track consecutive same path
        if self.last_path.as_deref() == Some(&normalized) {
            self.consecutive_same += 1;
        } else {
            self.consecutive_same = 1;
            self.last_path = Some(normalized.clone());
        }

        // Track scanner paths
        if is_scanner_path(path) {
            self.scanner_paths_hit += 1;
        }

        // Track API-only
        if path.starts_with("/api/") || path.starts_with("/api.") {
            self.api_only_count += 1;
        } else {
            self.api_only_count = 0; // Reset on non-API path
        }

        // Add to circular buffer
        self.recent_paths.push_back(PathEntry {
            path: normalized,
            method: method.to_string(),
            timestamp: now,
        });
        if self.recent_paths.len() > MAX_RECENT_PATHS {
            self.recent_paths.pop_front();
        }
    }

    fn is_stale(&self) -> bool {
        self.last_request.elapsed() > EVICTION_IDLE
    }
}

/// Result of session path analysis
#[derive(Debug, Clone)]
pub struct SessionPathResult {
    /// Total risk points from path analysis (0-60)
    pub risk_points: i32,
    /// Specific detections
    pub detections: Vec<SessionPathDetection>,
}

/// Individual detection
#[derive(Debug, Clone)]
pub struct SessionPathDetection {
    /// Detection type
    pub detection_type: SessionPathDetectionType,
    /// Risk points for this detection
    pub points: i32,
    /// Human-readable detail
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPathDetectionType {
    /// Same path repeated many times consecutively
    PathRepetition,
    /// Multiple scanner/probe paths visited
    ScannerSequence,
    /// All requests are API-only, no navigation
    ApiOnly,
    /// Very few unique paths across many requests
    LowDiversity,
}

/// Session Path Analyzer
pub struct SessionPathAnalyzer {
    /// `ShardedLru`: IP-keyed → bound HARD realtime (evict LRU O(1)). Pre-fix: DashMap
    /// con cap soft enforced solo nella cleanup periodica (retain stale + batch-evict O(n)).
    profiles: ShardedLru<IpAddr, SessionPathProfile>,
}

impl SessionPathAnalyzer {
    pub fn new() -> Self {
        Self {
            profiles: ShardedLru::new(MAX_TRACKED_IPS),
        }
    }

    /// Record a request and analyze the session path pattern
    pub fn analyze_and_record(&self, ip: IpAddr, path: &str, method: &str) -> SessionPathResult {
        // Tutto sotto UN solo lock dello shard (get-or-create + evict LRU O(1) se pieno).
        self.profiles
            .with_entry_mut(ip, SessionPathProfile::new, |profile| {
                self.analyze_profile(profile, path, method)
            })
    }

    /// Corpo dell'analisi su un profilo già recuperato/creato (sotto lock shard).
    fn analyze_profile(
        &self,
        profile: &mut SessionPathProfile,
        path: &str,
        method: &str,
    ) -> SessionPathResult {
        profile.record(path, method);

        let mut detections = Vec::new();

        // 1. Path repetition: same path > 5 times consecutively
        if profile.consecutive_same > 5 {
            detections.push(SessionPathDetection {
                detection_type: SessionPathDetectionType::PathRepetition,
                points: 15,
                detail: format!("Path repeated {} times consecutively", profile.consecutive_same),
            });
        }

        // 2. Scanner sequence: > 3 scanner paths hit
        if profile.scanner_paths_hit > 3 {
            detections.push(SessionPathDetection {
                detection_type: SessionPathDetectionType::ScannerSequence,
                points: 25,
                detail: format!("{} scanner paths accessed", profile.scanner_paths_hit),
            });
        }

        // 3. API-only: > 10 consecutive API requests without HTML navigation
        if profile.api_only_count > 10 {
            detections.push(SessionPathDetection {
                detection_type: SessionPathDetectionType::ApiOnly,
                points: 10,
                detail: format!("{} consecutive API-only requests", profile.api_only_count),
            });
        }

        // 4. Path diversity anomaly: < 3 unique paths in > 20 requests
        if profile.total_requests > 20 && profile.unique_paths.len() < 3 {
            detections.push(SessionPathDetection {
                detection_type: SessionPathDetectionType::LowDiversity,
                points: 10,
                detail: format!(
                    "Only {} unique paths across {} requests",
                    profile.unique_paths.len(),
                    profile.total_requests
                ),
            });
        }

        let risk_points = detections.iter().map(|d| d.points).sum::<i32>().min(60);

        SessionPathResult {
            risk_points,
            detections,
        }
    }

    /// Periodic RECLAIM of stale profiles. Il bound della mappa è strutturale in
    /// `ShardedLru` (evict LRU O(1)) → niente più batch-evict O(n) per il cap.
    pub fn cleanup(&self) {
        self.profiles.retain(|_, profile| !profile.is_stale());
    }

    /// Number of tracked sessions
    pub fn tracked_sessions(&self) -> usize {
        self.profiles.len()
    }
}

impl Default for SessionPathAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a path for comparison (replace dynamic segments)
fn normalize_path(path: &str) -> String {
    // Remove query string
    let path = path.split('?').next().unwrap_or(path);

    // Split into segments and normalize
    let segments: Vec<&str> = path.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|s| {
            // Replace UUIDs
            if s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4 {
                "*".to_string()
            }
            // Replace pure numeric segments
            else if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
                "*".to_string()
            } else {
                s.to_string()
            }
        })
        .collect();

    normalized.join("/")
}

/// Check if a path is a known scanner/probe target
fn is_scanner_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    SCANNER_PATHS.iter().any(|&scanner_path| {
        path_lower.starts_with(scanner_path) || path_lower == scanner_path
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 🚨 SESSION1/OOM: la mappa `profiles` (IP-keyed) è bounded realtime via ShardedLru
    /// (evict LRU O(1)), non solo via la cleanup periodica (retain + batch-evict O(n)).
    /// Mutation-verify: senza il cap ShardedLru → tracked_sessions() == 5000 invece di cap.
    #[test]
    fn profiles_bounded_realtime_under_ip_flood() {
        let a = SessionPathAnalyzer {
            profiles: ShardedLru::new(64), // multiplo dei 16 shard → capacity()==64
        };
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, b[2], b[3])); // 5000 IP distinti
            a.analyze_and_record(ip, "/x", "GET");
        }
        assert_eq!(a.tracked_sessions(), 64, "profiles non bounded realtime (got {})", a.tracked_sessions());
    }

    #[test]
    fn test_path_repetition_detection() {
        let analyzer = SessionPathAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Hit same path 7 times
        for _ in 0..7 {
            analyzer.analyze_and_record(ip, "/api/login", "POST");
        }

        let result = analyzer.analyze_and_record(ip, "/api/login", "POST");
        assert!(result.risk_points >= 15);
        assert!(result.detections.iter().any(|d| d.detection_type == SessionPathDetectionType::PathRepetition));
    }

    #[test]
    fn test_scanner_sequence_detection() {
        let analyzer = SessionPathAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let scanner_paths = ["/.env", "/wp-login.php", "/.git/config", "/phpmyadmin", "/actuator"];
        for path in &scanner_paths {
            analyzer.analyze_and_record(ip, path, "GET");
        }

        let result = analyzer.analyze_and_record(ip, "/solr", "GET");
        assert!(result.risk_points >= 25);
        assert!(result.detections.iter().any(|d| d.detection_type == SessionPathDetectionType::ScannerSequence));
    }

    #[test]
    fn test_api_only_detection() {
        let analyzer = SessionPathAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // 12 consecutive API requests
        for i in 0..12 {
            analyzer.analyze_and_record(ip, &format!("/api/endpoint{}", i), "GET");
        }

        let result = analyzer.analyze_and_record(ip, "/api/another", "GET");
        assert!(result.detections.iter().any(|d| d.detection_type == SessionPathDetectionType::ApiOnly));
    }

    #[test]
    fn test_low_diversity_detection() {
        let analyzer = SessionPathAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // 25 requests but only 2 unique paths
        for i in 0..25 {
            let path = if i % 2 == 0 { "/api/a" } else { "/api/b" };
            analyzer.analyze_and_record(ip, path, "GET");
        }

        let result = analyzer.analyze_and_record(ip, "/api/a", "GET");
        assert!(result.detections.iter().any(|d| d.detection_type == SessionPathDetectionType::LowDiversity));
    }

    #[test]
    fn test_normal_browsing_no_detection() {
        let analyzer = SessionPathAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Normal browsing pattern
        let paths = ["/", "/login", "/dashboard", "/api/orders", "/api/orders/123", "/settings"];
        for path in &paths {
            analyzer.analyze_and_record(ip, path, "GET");
        }

        let result = analyzer.analyze_and_record(ip, "/logout", "POST");
        assert_eq!(result.risk_points, 0);
        assert!(result.detections.is_empty());
    }

    #[test]
    fn test_path_normalization() {
        assert_eq!(normalize_path("/api/orders/123"), "/api/orders/*");
        assert_eq!(
            normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000/profile"),
            "/api/users/*/profile"
        );
        assert_eq!(normalize_path("/about?lang=it"), "/about");
    }

    #[test]
    fn test_scanner_path_detection() {
        assert!(is_scanner_path("/.env"));
        assert!(is_scanner_path("/.git/config"));
        assert!(is_scanner_path("/wp-login.php"));
        assert!(is_scanner_path("/phpmyadmin"));
        assert!(!is_scanner_path("/api/orders"));
        assert!(!is_scanner_path("/about"));
    }
}
