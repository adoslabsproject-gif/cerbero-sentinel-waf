// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! Honeypot Module — trap endpoints that attract and identify attackers.
//!
//! Exposes fake vulnerable endpoints that no legitimate user would access.
//! Any request to a honeypot is automatically flagged as malicious.
//!
//! Default honeypots:
//! - Admin panels: /admin, /wp-admin, /phpmyadmin, /cpanel
//! - Sensitive files: /.env, /.git/config, /wp-config.php, /debug.log
//! - API probes: /api/v1/admin, /graphql, /swagger.json, /actuator
//! - Scanner targets: /server-status, /xmlrpc.php, /solr, /console
//!
//! Custom honeypots can be added at runtime.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Record of a honeypot hit
#[derive(Debug, Clone)]
pub struct HoneypotHit {
    pub ip: IpAddr,
    pub path: String,
    pub method: String,
    pub timestamp: Instant,
    pub user_agent: Option<String>,
}

/// Honeypot detector
pub struct HoneypotDetector {
    /// Paths that are traps — any access = attacker
    trap_paths: Vec<String>,
    /// Exact match traps (faster lookup)
    exact_traps: std::collections::HashSet<String>,
    /// Prefix match traps (e.g., /wp-admin/)
    prefix_traps: Vec<String>,
    /// Extension traps (e.g., .php, .asp)
    extension_traps: Vec<String>,
    /// Recent hits per IP (for scoring)
    hits: DashMap<IpAddr, Vec<HoneypotHit>>,
    /// Custom response bodies (make traps look real)
    fake_responses: std::collections::HashMap<String, FakeResponse>,
}

/// Fake response to make honeypot look convincing
#[derive(Debug, Clone)]
pub struct FakeResponse {
    pub status_code: u16,
    pub body: String,
    pub content_type: String,
}

/// Default honeypot paths — things only attackers look for
const DEFAULT_EXACT_TRAPS: &[&str] = &[
    // Admin panels
    "/admin", "/administrator", "/admin.php", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/cpanel", "/plesk", "/webmail",
    // Sensitive files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.aws/credentials", "/.ssh/id_rsa", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/configuration.php",
    "/web.config", "/appsettings.json",
    "/debug.log", "/error.log", "/access.log",
    "/database.sql", "/dump.sql", "/backup.sql", "/db.sql",
    // API probes
    "/graphql", "/graphiql", "/playground",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger-ui", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/server-status", "/server-info",
    "/_debug", "/_profiler", "/_config",
    "/elmah.axd", "/trace.axd",
    "/solr/admin", "/console",
    // CMS/Framework
    "/xmlrpc.php", "/wp-cron.php", "/wp-includes/",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/", "/cgi-bin/php",
    // DevOps
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/Procfile", "/Jenkinsfile", "/.circleci/config.yml",
    "/terraform.tfstate",
    // Package managers
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
];

const DEFAULT_PREFIX_TRAPS: &[&str] = &[
    "/wp-admin/",
    "/wp-content/uploads/",
    "/wp-includes/",
    "/phpmyadmin/",
    "/.git/",
    "/.svn/",
    "/cgi-bin/",
    "/vendor/phpunit/",
];

const DEFAULT_EXTENSION_TRAPS: &[&str] = &[
    ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".bak", ".old", ".backup", ".save", ".orig",
    ".sql", ".db", ".sqlite",
    ".log", ".swp", ".swo",
];

impl HoneypotDetector {
    /// Create with default honeypot paths
    pub fn new() -> Self {
        let mut exact_traps = std::collections::HashSet::new();
        for path in DEFAULT_EXACT_TRAPS {
            exact_traps.insert(path.to_string());
        }

        let mut fake_responses = std::collections::HashMap::new();

        // Make .env look real
        fake_responses.insert("/.env".to_string(), FakeResponse {
            status_code: 200,
            body: "# FAKE — this is a honeypot\nDB_HOST=localhost\nDB_USER=root\nDB_PASS=changeme123\nSECRET_KEY=sk_fake_honeypot_trap\nAWS_ACCESS_KEY=AKIAFAKEKEY000000000\n".to_string(),
            content_type: "text/plain".to_string(),
        });

        // Make wp-login look real
        fake_responses.insert("/wp-login.php".to_string(), FakeResponse {
            status_code: 200,
            body: "<html><head><title>Log In &lsaquo; WordPress</title></head><body><form method='post'><label>Username</label><input name='log'><label>Password</label><input name='pwd' type='password'><input type='submit' value='Log In'></form></body></html>".to_string(),
            content_type: "text/html".to_string(),
        });

        // Make server-status look real
        fake_responses.insert("/server-status".to_string(), FakeResponse {
            status_code: 200,
            body: "Apache Server Status\nServer uptime: 45 days 3 hours\nTotal accesses: 1234567\nCPU Usage: u12.3 s4.5\n".to_string(),
            content_type: "text/plain".to_string(),
        });

        Self {
            trap_paths: DEFAULT_EXACT_TRAPS.iter().map(|s| s.to_string()).collect(),
            exact_traps,
            prefix_traps: DEFAULT_PREFIX_TRAPS.iter().map(|s| s.to_string()).collect(),
            extension_traps: DEFAULT_EXTENSION_TRAPS.iter().map(|s| s.to_string()).collect(),
            hits: DashMap::new(),
            fake_responses,
        }
    }

    /// Check if a path is a honeypot. Returns true if it's a trap.
    pub fn is_trap(&self, path: &str) -> bool {
        let lower = path.to_lowercase();

        // Exact match (O(1))
        if self.exact_traps.contains(&lower) {
            return true;
        }

        // Prefix match
        for prefix in &self.prefix_traps {
            if lower.starts_with(prefix) {
                return true;
            }
        }

        // Extension match
        for ext in &self.extension_traps {
            if lower.ends_with(ext) {
                return true;
            }
        }

        false
    }

    /// Record a honeypot hit and return the trap score
    pub fn record_hit(&self, ip: IpAddr, path: &str, method: &str, user_agent: Option<&str>) -> f64 {
        let hit = HoneypotHit {
            ip,
            path: path.to_string(),
            method: method.to_string(),
            timestamp: Instant::now(),
            user_agent: user_agent.map(|s| s.to_string()),
        };

        tracing::warn!(
            ip = %ip,
            path = path,
            method = method,
            "Honeypot triggered"
        );

        let mut hits = self.hits.entry(ip).or_insert_with(Vec::new);
        hits.push(hit);
        let hit_count = hits.len();

        // Score based on number of honeypot hits
        // 1 hit = 0.7 (could be accidental)
        // 2 hits = 0.85 (unlikely accidental)
        // 3+ hits = 0.95 (definitely scanning)
        match hit_count {
            1 => 0.7,
            2 => 0.85,
            _ => 0.95,
        }
    }

    /// Get fake response for a trap path (makes the honeypot convincing)
    pub fn get_fake_response(&self, path: &str) -> Option<&FakeResponse> {
        self.fake_responses.get(path)
    }

    /// Get all hits for an IP
    pub fn get_hits(&self, ip: &IpAddr) -> Vec<HoneypotHit> {
        self.hits.get(ip).map(|h| h.clone()).unwrap_or_default()
    }

    /// Get total hit count across all IPs
    pub fn total_hits(&self) -> usize {
        self.hits.iter().map(|e| e.value().len()).sum()
    }

    /// Get IPs that have triggered honeypots
    pub fn get_trapped_ips(&self) -> Vec<(IpAddr, usize)> {
        self.hits.iter()
            .map(|e| (*e.key(), e.value().len()))
            .collect()
    }

    /// Add a custom trap path
    pub fn add_trap(&mut self, path: &str) {
        self.exact_traps.insert(path.to_lowercase());
        self.trap_paths.push(path.to_string());
    }

    /// Add a custom fake response
    pub fn add_fake_response(&mut self, path: &str, status: u16, body: &str, content_type: &str) {
        self.fake_responses.insert(path.to_string(), FakeResponse {
            status_code: status,
            body: body.to_string(),
            content_type: content_type.to_string(),
        });
    }

    /// Cleanup old hits (call periodically)
    pub fn cleanup(&self, max_age_secs: u64) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(max_age_secs);
        for mut entry in self.hits.iter_mut() {
            entry.value_mut().retain(|h| h.timestamp > cutoff);
        }
        // Remove empty entries
        self.hits.retain(|_, v| !v.is_empty());
    }
}

impl Default for HoneypotDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_exact_trap() {
        let detector = HoneypotDetector::new();
        assert!(detector.is_trap("/.env"));
        assert!(detector.is_trap("/wp-admin"));
        assert!(detector.is_trap("/phpmyadmin"));
        assert!(detector.is_trap("/actuator"));
    }

    #[test]
    fn test_prefix_trap() {
        let detector = HoneypotDetector::new();
        assert!(detector.is_trap("/wp-admin/edit.php"));
        assert!(detector.is_trap("/.git/objects/pack"));
        assert!(detector.is_trap("/cgi-bin/test.sh"));
    }

    #[test]
    fn test_extension_trap() {
        let detector = HoneypotDetector::new();
        assert!(detector.is_trap("/index.php"));
        assert!(detector.is_trap("/backup.sql"));
        assert!(detector.is_trap("/config.bak"));
    }

    #[test]
    fn test_clean_path() {
        let detector = HoneypotDetector::new();
        assert!(!detector.is_trap("/api/v1/posts"));
        assert!(!detector.is_trap("/"));
        assert!(!detector.is_trap("/about"));
        assert!(!detector.is_trap("/api/v1/chat"));
    }

    #[test]
    fn test_hit_scoring() {
        let detector = HoneypotDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let score1 = detector.record_hit(ip, "/.env", "GET", None);
        assert!(score1 >= 0.7);

        let score2 = detector.record_hit(ip, "/wp-admin", "GET", None);
        assert!(score2 >= 0.85);

        let score3 = detector.record_hit(ip, "/phpmyadmin", "GET", None);
        assert!(score3 >= 0.95);
    }

    #[test]
    fn test_fake_response() {
        let detector = HoneypotDetector::new();
        let resp = detector.get_fake_response("/.env");
        assert!(resp.is_some());
        assert!(resp.unwrap().body.contains("DB_HOST"));
    }

    #[test]
    fn test_case_insensitive() {
        let detector = HoneypotDetector::new();
        assert!(detector.is_trap("/.ENV"));
        assert!(detector.is_trap("/WP-ADMIN"));
        assert!(detector.is_trap("/PhpMyAdmin"));
    }
}
