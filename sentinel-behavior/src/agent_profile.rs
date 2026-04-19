//! Agent Profiling
//!
//! Per-agent behavioral baselines and deviation detection.
//! Tracks request patterns, timing, and resource usage.

use sentinel_core::{AgentId, BehaviorConfig, Request, SentinelError};
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Result of agent behavior analysis
#[derive(Debug, Clone)]
pub struct AgentBehavior {
    /// Whether behavior is anomalous
    pub is_anomalous: bool,
    /// Whether request velocity exceeded
    pub velocity_exceeded: bool,
    /// Pattern deviation score (0.0 - 1.0)
    pub pattern_deviation: f64,
    /// Total requests in window
    pub request_count: usize,
    /// Average request interval
    pub avg_interval: Duration,
    /// Most common endpoints
    pub common_endpoints: Vec<String>,
}

/// Agent profile data
#[derive(Debug, Clone)]
struct AgentProfile {
    /// Request history (timestamps)
    request_times: VecDeque<Instant>,
    /// Endpoint frequency
    endpoint_counts: std::collections::HashMap<String, usize>,
    /// Request intervals
    intervals: VecDeque<Duration>,
    /// Last request time
    last_request: Option<Instant>,
    /// Created at
    created_at: Instant,
    /// Total requests
    total_requests: u64,
}

impl AgentProfile {
    fn new() -> Self {
        Self {
            request_times: VecDeque::with_capacity(1000),
            endpoint_counts: std::collections::HashMap::new(),
            intervals: VecDeque::with_capacity(100),
            last_request: None,
            created_at: Instant::now(),
            total_requests: 0,
        }
    }

    fn record_request(&mut self, endpoint: &str, window: Duration) {
        let now = Instant::now();

        // Record interval
        if let Some(last) = self.last_request {
            let interval = now.duration_since(last);
            self.intervals.push_back(interval);
            if self.intervals.len() > 100 {
                self.intervals.pop_front();
            }
        }

        // Record time
        self.request_times.push_back(now);
        self.last_request = Some(now);
        self.total_requests += 1;

        // Clean old entries
        let cutoff = now - window;
        while let Some(front) = self.request_times.front() {
            if *front < cutoff {
                self.request_times.pop_front();
            } else {
                break;
            }
        }

        // Record endpoint
        *self.endpoint_counts.entry(endpoint.to_string()).or_insert(0) += 1;
    }

    fn get_request_count(&self) -> usize {
        self.request_times.len()
    }

    fn get_avg_interval(&self) -> Duration {
        if self.intervals.is_empty() {
            return Duration::from_secs(0);
        }

        let total: Duration = self.intervals.iter().sum();
        total / self.intervals.len() as u32
    }

    fn get_common_endpoints(&self, n: usize) -> Vec<String> {
        let mut endpoints: Vec<_> = self.endpoint_counts.iter().collect();
        endpoints.sort_by(|a, b| b.1.cmp(a.1));
        endpoints.into_iter().take(n).map(|(k, _)| k.clone()).collect()
    }

    fn calculate_pattern_deviation(&self, endpoint: &str) -> f64 {
        let total: usize = self.endpoint_counts.values().sum();
        if total == 0 {
            return 0.0;
        }

        let count = self.endpoint_counts.get(endpoint).copied().unwrap_or(0);
        let expected_ratio = count as f64 / total as f64;

        // If this is a new endpoint not seen before, higher deviation
        if count == 0 && self.total_requests > 10 {
            return 0.8;
        }

        // Calculate deviation based on access pattern
        // Low frequency endpoints accessed have higher deviation
        if expected_ratio < 0.01 && self.total_requests > 100 {
            return 0.6;
        }

        0.0
    }
}

/// Agent profiler for behavioral analysis
pub struct AgentProfiler {
    /// Agent profiles
    profiles: Arc<DashMap<AgentId, AgentProfile>>,
    /// Configuration
    config: BehaviorConfig,
    /// Window for tracking
    window: Duration,
    /// Maximum requests per window
    max_velocity: usize,
}

impl AgentProfiler {
    /// Create new profiler
    pub fn new(config: &BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            profiles: Arc::new(DashMap::new()),
            config: config.clone(),
            window: Duration::from_secs(config.profile_window_secs),
            max_velocity: config.max_requests_per_window,
        })
    }

    /// Analyze agent behavior
    pub async fn analyze(
        &self,
        agent_id: &AgentId,
        request: &Request,
    ) -> Result<AgentBehavior, SentinelError> {
        let profile = self.profiles
            .entry(agent_id.clone())
            .or_insert_with(AgentProfile::new);

        let request_count = profile.get_request_count();
        let velocity_exceeded = request_count >= self.max_velocity;
        let pattern_deviation = profile.calculate_pattern_deviation(&request.path);
        let avg_interval = profile.get_avg_interval();
        let common_endpoints = profile.get_common_endpoints(5);

        // Determine if behavior is anomalous
        let is_anomalous = velocity_exceeded
            || pattern_deviation > self.config.deviation_threshold
            || (avg_interval < Duration::from_millis(100) && request_count > 10);

        Ok(AgentBehavior {
            is_anomalous,
            velocity_exceeded,
            pattern_deviation,
            request_count,
            avg_interval,
            common_endpoints,
        })
    }

    /// Record a request
    pub async fn record(
        &self,
        agent_id: &AgentId,
        request: &Request,
    ) -> Result<(), SentinelError> {
        let mut profile = self.profiles
            .entry(agent_id.clone())
            .or_insert_with(AgentProfile::new);

        profile.record_request(&request.path, self.window);

        Ok(())
    }

    /// Get agent profile
    pub async fn get_profile(&self, agent_id: &AgentId) -> Option<AgentBehavior> {
        self.profiles.get(agent_id).map(|profile| {
            AgentBehavior {
                is_anomalous: false,
                velocity_exceeded: false,
                pattern_deviation: 0.0,
                request_count: profile.get_request_count(),
                avg_interval: profile.get_avg_interval(),
                common_endpoints: profile.get_common_endpoints(5),
            }
        })
    }

    /// Clean stale profiles
    pub async fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.profiles.retain(|_, profile| {
            now.duration_since(profile.created_at) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_profiler() -> AgentProfiler {
        let config = BehaviorConfig::default();
        AgentProfiler::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_new_agent_profile() {
        let profiler = create_profiler();
        let agent_id = AgentId::new();
        let request = Request {
            path: "/api/posts".to_string(),
            ..Default::default()
        };

        let behavior = profiler.analyze(&agent_id, &request).await.unwrap();
        assert!(!behavior.is_anomalous);
        assert!(!behavior.velocity_exceeded);
    }

    #[tokio::test]
    async fn test_velocity_detection() {
        let config = BehaviorConfig {
            max_requests_per_window: 5,
            ..Default::default()
        };
        let profiler = AgentProfiler::new(&config).unwrap();
        let agent_id = AgentId::new();

        // Make multiple requests
        for _ in 0..10 {
            let request = Request {
                path: "/api/posts".to_string(),
                ..Default::default()
            };
            profiler.record(&agent_id, &request).await.unwrap();
        }

        let request = Request {
            path: "/api/posts".to_string(),
            ..Default::default()
        };
        let behavior = profiler.analyze(&agent_id, &request).await.unwrap();
        assert!(behavior.velocity_exceeded);
        assert!(behavior.is_anomalous);
    }
}
