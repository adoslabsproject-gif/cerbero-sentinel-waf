// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! SENTINEL Server
//!
//! HTTP server exposing SENTINEL WAF functionality:
//! - REST API for request analysis
//! - Middleware integration (nginx auth_request)
//! - Health checks and metrics
//!
//! 4-layer defense: Edge → Neural → Behavioral → Response

pub mod middleware;
pub mod api;
pub mod metrics;

use sentinel_core::{SentinelConfig, SentinelError};
use sentinel_edge::EdgeShield;
use sentinel_neural::NeuralDefense;
use sentinel_behavior::BehavioralAnalysis;
use sentinel_response::ResponseLayer;
use std::sync::Arc;

/// SENTINEL WAF — 4-layer AI-native security system
pub struct Sentinel {
    #[allow(dead_code)]
    config: SentinelConfig,
    /// Layer 1: Edge Shield — rate limiting, IP intel, DDoS protection
    edge: Arc<EdgeShield>,
    /// Layer 2: Neural Defense — prompt injection, toxicity, encoding attacks
    neural: Arc<NeuralDefense>,
    /// Layer 3: Behavioral Analysis — agent profiling, anomaly detection, coordination
    behavior: Arc<BehavioralAnalysis>,
    /// Layer 4: Response — adaptive actions, bans, challenges, escalation
    response: Arc<ResponseLayer>,
}

impl Sentinel {
    /// Create new SENTINEL instance with all 4 layers
    pub fn new(config: SentinelConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            edge: Arc::new(EdgeShield::new(config.edge.clone())?),
            neural: Arc::new(NeuralDefense::new(config.neural.clone())?),
            behavior: Arc::new(BehavioralAnalysis::new(config.behavior.clone())?),
            response: Arc::new(ResponseLayer::new(config.response.clone())?),
            config,
        })
    }

    /// Process a request through all 4 layers.
    /// Returns the action to take (Allow, Block, Challenge, RateLimit).
    pub async fn process(
        &self,
        request: &sentinel_core::Request,
        agent_id: Option<&sentinel_core::AgentId>,
    ) -> Result<sentinel_core::Action, SentinelError> {
        let start = std::time::Instant::now();

        // Layer 1: Edge Shield (< 1ms)
        let edge_score = self.edge.analyze(request).await?;

        // Fast path: Critical threats blocked immediately at edge
        if edge_score.level == sentinel_core::RiskLevel::Critical {
            let action = self.response
                .determine_action(request, &edge_score, agent_id)
                .await?;

            tracing::warn!(
                latency_us = start.elapsed().as_micros(),
                level = "edge",
                risk = ?edge_score.level,
                "Request blocked at edge"
            );

            return Ok(action);
        }

        // Layer 2: Neural Defense (< 5ms)
        let neural_score = self.neural.analyze(request).await?;

        // Combine scores
        let mut combined_score = edge_score.clone();
        combined_score.neural_score = neural_score.neural_score;
        combined_score.flags.extend(neural_score.flags);
        combined_score.update_level();

        // Fast path: High threats challenged after neural
        if combined_score.level >= sentinel_core::RiskLevel::High {
            let action = self.response
                .determine_action(request, &combined_score, agent_id)
                .await?;

            tracing::warn!(
                latency_us = start.elapsed().as_micros(),
                level = "neural",
                risk = ?combined_score.level,
                "Request flagged by neural defense"
            );

            return Ok(action);
        }

        // Layer 3: Behavioral Analysis (< 10ms)
        let behavior_score = self.behavior.analyze(request, agent_id).await?;
        combined_score.behavioral_score = behavior_score.behavioral_score;
        combined_score.flags.extend(behavior_score.flags);
        combined_score.update_level();

        // Record for learning
        self.behavior.record(request, agent_id).await?;

        // Layer 4: Determine final action
        let action = self.response
            .determine_action(request, &combined_score, agent_id)
            .await?;

        let latency = start.elapsed();

        if combined_score.level >= sentinel_core::RiskLevel::Medium {
            tracing::warn!(
                latency_us = latency.as_micros(),
                edge_score = edge_score.edge_score,
                neural_score = neural_score.neural_score,
                behavior_score = behavior_score.behavioral_score,
                total_score = combined_score.total_score(),
                risk = ?combined_score.level,
                action = ?action,
                "Request processed"
            );
        }

        // Record metrics
        metrics::record_request(latency, &combined_score, &action);

        Ok(action)
    }

    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, SentinelError> {
        self.response.verify_challenge(challenge_id, response).await
    }

    /// Get health status
    pub fn health(&self) -> HealthStatus {
        HealthStatus {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            edge_ready: true,
            neural_ready: true,
            behavior_ready: true,
            response_ready: true,
        }
    }

    /// Get statistics
    pub fn stats(&self) -> Stats {
        let response_stats = self.response.get_stats();

        Stats {
            active_bans: response_stats.active_bans,
            pending_challenges: response_stats.pending_challenges,
            escalations_today: response_stats.escalations_today,
        }
    }

    pub fn edge(&self) -> &EdgeShield { &self.edge }
    pub fn neural(&self) -> &NeuralDefense { &self.neural }
    pub fn behavior(&self) -> &BehavioralAnalysis { &self.behavior }
    pub fn response(&self) -> &ResponseLayer { &self.response }
}

/// Health status
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub edge_ready: bool,
    pub neural_ready: bool,
    pub behavior_ready: bool,
    pub response_ready: bool,
}

/// Statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub active_bans: usize,
    pub pending_challenges: usize,
    pub escalations_today: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sentinel_creation() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config);
        assert!(sentinel.is_ok());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();
        let health = sentinel.health();
        assert_eq!(health.status, "healthy");
        assert!(health.behavior_ready);
    }

    #[tokio::test]
    async fn test_clean_request() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        let request = sentinel_core::Request {
            path: "/api/posts".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let action = sentinel.process(&request, None).await.unwrap();
        assert!(matches!(action, sentinel_core::Action::Allow));
    }
}
