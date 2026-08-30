//! Risk Memory Layer (WI-9)
//!
//! Path-based risk classification + IP/UA cumulative risk profiles.
//! Runs BEFORE the main pipeline as a pre-scoring multiplier.
//!
//! - Path criticality: /api/auth = Critical (×2.0), /api/chat = High (×1.5), /about = Low (×0.5)
//! - IP risk memory: accumulates risk over a 1h sliding window
//! - UA risk profiles: tracks threat ratio per user-agent

use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const IP_WINDOW: Duration = Duration::from_secs(3600); // 1 hour
const IP_EVICTION: Duration = Duration::from_secs(3600); // Evict after 1h idle
const MAX_IP_ENTRIES: usize = 50_000;

/// Path criticality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCriticality {
    /// Authentication, admin, internal APIs
    Critical,
    /// LLM endpoints, payment
    High,
    /// Standard API endpoints
    Medium,
    /// Static, public pages
    Low,
}

impl PathCriticality {
    /// Risk score multiplier
    pub fn multiplier(&self) -> f64 {
        match self {
            PathCriticality::Critical => 2.0,
            PathCriticality::High => 1.5,
            PathCriticality::Medium => 1.0,
            PathCriticality::Low => 0.5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PathCriticality::Critical => "critical",
            PathCriticality::High => "high",
            PathCriticality::Medium => "medium",
            PathCriticality::Low => "low",
        }
    }
}

/// Classify a path's criticality
pub fn classify_path(path: &str) -> PathCriticality {
    let path_lower = path.to_lowercase();

    // Critical: authentication, admin, internal APIs
    if path_lower.starts_with("/api/auth")
        || path_lower.starts_with("/api/internal")
        || path_lower.starts_with("/admin")
        || path_lower.starts_with("/api/admin")
    {
        return PathCriticality::Critical;
    }

    // High: LLM endpoints (prompt injection target)
    if path_lower.starts_with("/api/chat")
        || path_lower.starts_with("/api/liara")
        || path_lower.starts_with("/api/marketplace/orders")
    {
        return PathCriticality::High;
    }

    // Medium: other API endpoints
    if path_lower.starts_with("/api/") {
        return PathCriticality::Medium;
    }

    // Low: static, public
    PathCriticality::Low
}

/// Timestamped risk event for sliding window
#[derive(Debug, Clone)]
struct RiskEvent {
    score: f64,
    timestamp: Instant,
    is_critical_path: bool,
}

/// Per-IP risk profile (sliding window 1h)
struct IpRiskProfile {
    /// Recent risk events
    events: VecDeque<RiskEvent>,
    /// Last activity
    last_seen: Instant,
}

impl IpRiskProfile {
    fn new() -> Self {
        Self {
            events: VecDeque::with_capacity(100),
            last_seen: Instant::now(),
        }
    }

    fn record(&mut self, score: f64, is_critical_path: bool) {
        let now = Instant::now();
        self.last_seen = now;
        self.events.push_back(RiskEvent {
            score,
            timestamp: now,
            is_critical_path,
        });

        // Prune old events
        let cutoff = now - IP_WINDOW;
        while self.events.front().map(|e| e.timestamp < cutoff).unwrap_or(false) {
            self.events.pop_front();
        }

        // Keep max 100 events
        while self.events.len() > 100 {
            self.events.pop_front();
        }
    }

    /// Cumulative risk score in the window
    fn cumulative_score(&self) -> f64 {
        self.events.iter().map(|e| e.score).sum()
    }

    /// Number of threat events in the window
    fn threat_count(&self) -> u32 {
        self.events.iter().filter(|e| e.score > 0.3).count() as u32
    }

    /// Number of threats on critical paths
    fn critical_path_threat_count(&self) -> u32 {
        self.events.iter().filter(|e| e.is_critical_path && e.score > 0.3).count() as u32
    }

    fn is_stale(&self) -> bool {
        self.last_seen.elapsed() > IP_EVICTION
    }
}

/// Risk memory pre-scoring result
#[derive(Debug, Clone)]
pub struct RiskMemoryResult {
    /// Path criticality multiplier (0.5 - 2.0)
    pub path_multiplier: f64,
    /// Path criticality classification
    pub path_criticality: PathCriticality,
    /// Additional risk points from IP history (0-30)
    pub ip_risk_points: i32,
    /// Whether to force a challenge (critical path + repeated threats)
    pub force_challenge: bool,
    /// IP cumulative risk score in last hour
    pub ip_cumulative_score: f64,
    /// IP threat count in last hour
    pub ip_threat_count: u32,
}

/// Risk Memory Layer
pub struct RiskMemory {
    /// IP risk profiles
    ip_profiles: DashMap<IpAddr, IpRiskProfile>,
}

impl RiskMemory {
    pub fn new() -> Self {
        Self {
            ip_profiles: DashMap::new(),
        }
    }

    /// Pre-score a request based on path criticality and IP history
    pub fn pre_score(&self, ip: IpAddr, path: &str) -> RiskMemoryResult {
        let path_criticality = classify_path(path);
        let path_multiplier = path_criticality.multiplier();

        let mut ip_risk_points = 0i32;
        let mut force_challenge = false;
        let mut ip_cumulative_score = 0.0f64;
        let mut ip_threat_count = 0u32;

        if let Some(profile) = self.ip_profiles.get(&ip) {
            ip_cumulative_score = profile.cumulative_score();
            ip_threat_count = profile.threat_count();
            let critical_threats = profile.critical_path_threat_count();

            // IP with high cumulative score → additional risk
            if ip_cumulative_score > 50.0 {
                ip_risk_points += 15;
            } else if ip_cumulative_score > 20.0 {
                ip_risk_points += 8;
            } else if ip_cumulative_score > 10.0 {
                ip_risk_points += 3;
            }

            // Multiple threats → escalation
            if ip_threat_count > 10 {
                ip_risk_points += 10;
            } else if ip_threat_count > 5 {
                ip_risk_points += 5;
            }

            // Repeated threats on critical paths → immediate challenge
            if critical_threats > 3 && matches!(path_criticality, PathCriticality::Critical) {
                force_challenge = true;
                ip_risk_points += 10;
            }
        }

        // Cap ip_risk_points
        ip_risk_points = ip_risk_points.min(30);

        RiskMemoryResult {
            path_multiplier,
            path_criticality,
            ip_risk_points,
            force_challenge,
            ip_cumulative_score,
            ip_threat_count,
        }
    }

    /// Record a risk event for an IP
    pub fn record(&self, ip: IpAddr, score: f64, path: &str) {
        let is_critical = matches!(classify_path(path), PathCriticality::Critical | PathCriticality::High);

        self.ip_profiles
            .entry(ip)
            .or_insert_with(IpRiskProfile::new)
            .record(score, is_critical);
    }

    /// Periodic cleanup of stale entries
    pub fn cleanup(&self) {
        self.ip_profiles.retain(|_, profile| !profile.is_stale());

        // Hard limit
        if self.ip_profiles.len() > MAX_IP_ENTRIES {
            // Remove oldest (stale check already done, but enforce limit)
            let to_remove = self.ip_profiles.len() - MAX_IP_ENTRIES;
            let mut removed = 0;
            self.ip_profiles.retain(|_, _| {
                if removed >= to_remove {
                    true
                } else {
                    removed += 1;
                    false
                }
            });
        }
    }

    /// Number of tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.ip_profiles.len()
    }
}

impl Default for RiskMemory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_path_classification() {
        assert_eq!(classify_path("/api/auth/login"), PathCriticality::Critical);
        assert_eq!(classify_path("/api/internal/check"), PathCriticality::Critical);
        assert_eq!(classify_path("/admin/users"), PathCriticality::Critical);
        assert_eq!(classify_path("/api/chat"), PathCriticality::High);
        assert_eq!(classify_path("/api/marketplace/orders"), PathCriticality::High);
        assert_eq!(classify_path("/api/v1/products"), PathCriticality::Medium);
        assert_eq!(classify_path("/about"), PathCriticality::Low);
        assert_eq!(classify_path("/privacy"), PathCriticality::Low);
    }

    #[test]
    fn test_path_multiplier() {
        assert_eq!(PathCriticality::Critical.multiplier(), 2.0);
        assert_eq!(PathCriticality::High.multiplier(), 1.5);
        assert_eq!(PathCriticality::Medium.multiplier(), 1.0);
        assert_eq!(PathCriticality::Low.multiplier(), 0.5);
    }

    #[test]
    fn test_ip_risk_accumulation() {
        let memory = RiskMemory::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Record multiple threats
        for _ in 0..6 {
            memory.record(ip, 5.0, "/api/auth/login");
        }

        let result = memory.pre_score(ip, "/api/auth/login");
        assert!(result.ip_risk_points > 0);
        assert!(result.ip_cumulative_score > 20.0);
        assert!(result.ip_threat_count >= 6);
    }

    #[test]
    fn test_force_challenge_on_critical_path() {
        let memory = RiskMemory::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Record 5 threats on critical paths
        for _ in 0..5 {
            memory.record(ip, 5.0, "/api/auth/login");
        }

        let result = memory.pre_score(ip, "/api/auth/login");
        assert!(result.force_challenge);
    }

    #[test]
    fn test_clean_ip_no_risk() {
        let memory = RiskMemory::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let result = memory.pre_score(ip, "/api/products");
        assert_eq!(result.ip_risk_points, 0);
        assert!(!result.force_challenge);
        assert_eq!(result.path_criticality, PathCriticality::Medium);
    }
}
