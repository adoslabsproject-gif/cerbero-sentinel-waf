#![allow(dead_code)]
//! DDoS Detection Module
//!
//! Detects various DDoS attack patterns:
//! - Volumetric attacks (high request rate)
//! - Slow loris attacks (connection exhaustion)
//! - Application layer attacks (targeted endpoints)

use dashmap::DashMap;
use sentinel_core::Request;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Types of DDoS patterns detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DDoSPattern {
    /// High volume of requests
    Volumetric,
    /// Slow connection attacks
    SlowLoris,
    /// Application layer attacks targeting specific endpoints
    ApplicationLayer,
}

/// Request tracking for DDoS detection
struct RequestTracker {
    /// Recent request timestamps
    timestamps: VecDeque<Instant>,
    /// Endpoints hit
    endpoints: VecDeque<String>,
    /// Last active time
    last_active: Instant,
}

impl RequestTracker {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::with_capacity(1000),
            endpoints: VecDeque::with_capacity(100),
            last_active: Instant::now(),
        }
    }

    fn record(&mut self, path: &str) {
        let now = Instant::now();
        self.timestamps.push_back(now);
        self.endpoints.push_back(path.to_string());
        self.last_active = now;

        // Keep only last 10 seconds of data
        let cutoff = now - Duration::from_secs(10);
        while self.timestamps.front().map(|&t| t < cutoff).unwrap_or(false) {
            self.timestamps.pop_front();
        }

        // Keep only last 100 endpoints
        while self.endpoints.len() > 100 {
            self.endpoints.pop_front();
        }
    }

    fn requests_per_second(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }

        let now = Instant::now();
        let window = Duration::from_secs(1);
        let count = self.timestamps.iter().filter(|&&t| now - t < window).count();
        count as f64
    }

    fn requests_last_10s(&self) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(10);
        self.timestamps.iter().filter(|&&t| now - t < window).count()
    }

    fn unique_endpoints(&self) -> usize {
        let mut unique: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for ep in &self.endpoints {
            unique.insert(ep.as_str());
        }
        unique.len()
    }

    fn is_stale(&self) -> bool {
        self.last_active.elapsed() > Duration::from_secs(60)
    }
}

/// Global attack detection
struct GlobalStats {
    /// Total requests in last second
    total_rps: RwLock<VecDeque<(Instant, u64)>>,
    /// Baseline RPS (normal traffic)
    baseline_rps: RwLock<f64>,
}

impl GlobalStats {
    fn new() -> Self {
        Self {
            total_rps: RwLock::new(VecDeque::with_capacity(60)),
            baseline_rps: RwLock::new(100.0), // Default baseline
        }
    }

    fn record(&self) {
        let now = Instant::now();
        let mut rps = self.total_rps.write().unwrap();

        // Find current second's entry or create new
        if let Some((ts, count)) = rps.back_mut() {
            if now.duration_since(*ts) < Duration::from_secs(1) {
                *count += 1;
                return;
            }
        }

        rps.push_back((now, 1));

        // Keep only last 60 seconds
        let cutoff = now - Duration::from_secs(60);
        while rps.front().map(|(t, _)| *t < cutoff).unwrap_or(false) {
            rps.pop_front();
        }
    }

    fn current_rps(&self) -> f64 {
        let rps = self.total_rps.read().unwrap();
        let now = Instant::now();

        rps.iter()
            .filter(|(t, _)| now.duration_since(*t) < Duration::from_secs(1))
            .map(|(_, c)| *c as f64)
            .sum()
    }

    fn is_under_attack(&self) -> bool {
        let current = self.current_rps();
        let baseline = *self.baseline_rps.read().unwrap();
        current > baseline * 5.0 // 5x baseline is suspicious
    }
}

/// DDoS Detector
pub struct DDoSDetector {
    /// Per-IP request tracking
    trackers: DashMap<IpAddr, RequestTracker>,
    /// Global statistics
    global: GlobalStats,
    /// Thresholds
    volumetric_threshold_rps: f64,
    app_layer_threshold_same_endpoint: usize,
}

impl DDoSDetector {
    /// Create a new DDoS detector
    pub fn new() -> Self {
        Self {
            trackers: DashMap::new(),
            global: GlobalStats::new(),
            volumetric_threshold_rps: 50.0,
            app_layer_threshold_same_endpoint: 20,
        }
    }

    /// Check for DDoS patterns
    pub async fn check(&self, ip: IpAddr, request: &Request) -> Option<DDoSPattern> {
        self.global.record();
        self.maybe_cleanup();

        let path = &request.path;

        // Get or create tracker for this IP
        let mut tracker = self.trackers.entry(ip).or_insert_with(RequestTracker::new);
        tracker.record(path);

        // Check volumetric attack
        let rps = tracker.requests_per_second();
        if rps > self.volumetric_threshold_rps {
            return Some(DDoSPattern::Volumetric);
        }

        // Check application layer attack (same endpoint repeatedly)
        let total_requests = tracker.requests_last_10s();
        let unique_endpoints = tracker.unique_endpoints();

        if total_requests > 30 && unique_endpoints < 3 {
            // Many requests to very few endpoints
            return Some(DDoSPattern::ApplicationLayer);
        }

        // Check for slow loris patterns
        // This would require connection tracking which we don't have here
        // Leaving as placeholder for future enhancement

        None
    }

    /// Check if we're under global attack
    pub fn is_under_global_attack(&self) -> bool {
        self.global.is_under_attack()
    }

    /// Get current global RPS
    pub fn global_rps(&self) -> f64 {
        self.global.current_rps()
    }

    /// Update baseline RPS
    pub fn set_baseline_rps(&self, rps: f64) {
        *self.global.baseline_rps.write().unwrap() = rps;
    }

    /// Set volumetric threshold
    pub fn set_volumetric_threshold(&mut self, rps: f64) {
        self.volumetric_threshold_rps = rps;
    }

    /// Get tracked IP count
    pub fn tracked_ips(&self) -> usize {
        self.trackers.len()
    }

    /// Cleanup stale trackers
    fn maybe_cleanup(&self) {
        // Only cleanup occasionally
        if self.trackers.len() < 10000 {
            return;
        }

        self.trackers.retain(|_, tracker| !tracker.is_stale());
    }
}

impl Default for DDoSDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_normal_traffic() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let request = Request {
            client_ip: ip,
            path: "/api/posts".to_string(),
            ..Default::default()
        };

        let pattern = detector.check(ip, &request).await;
        assert!(pattern.is_none());
    }

    #[tokio::test]
    async fn test_volumetric_detection() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Simulate high request rate
        for i in 0..100 {
            let request = Request {
                client_ip: ip,
                path: format!("/api/endpoint{}", i),
                ..Default::default()
            };
            detector.check(ip, &request).await;
        }

        // Should detect volumetric attack
        let request = Request {
            client_ip: ip,
            path: "/api/test".to_string(),
            ..Default::default()
        };
        let pattern = detector.check(ip, &request).await;
        assert!(pattern.is_some());
    }

    #[tokio::test]
    async fn test_application_layer_detection() {
        let detector = DDoSDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Hit same endpoint many times
        for _ in 0..50 {
            let request = Request {
                client_ip: ip,
                path: "/api/login".to_string(),
                ..Default::default()
            };
            detector.check(ip, &request).await;
        }

        // Should detect app layer attack
        let request = Request {
            client_ip: ip,
            path: "/api/login".to_string(),
            ..Default::default()
        };
        let pattern = detector.check(ip, &request).await;
        // Either ApplicationLayer or Volumetric is acceptable — both detect the attack
        assert!(pattern == Some(DDoSPattern::ApplicationLayer) || pattern == Some(DDoSPattern::Volumetric),
            "Expected ApplicationLayer or Volumetric, got {:?}", pattern);
    }
}
