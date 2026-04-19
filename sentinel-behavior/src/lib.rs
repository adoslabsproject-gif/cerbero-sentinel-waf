// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! SENTINEL Behavioral Analysis - Layer 3
//!
//! Agent behavior profiling and anomaly detection:
//! - Per-agent behavioral baselines
//! - Anomaly detection (Isolation Forest)
//! - Coordinated attack detection (DBSCAN clustering)
//! - Session analysis

pub mod agent_profile;
pub mod anomaly;
pub mod coordination;
pub mod session;

use sentinel_core::{AgentId, Request, LayerRiskScore as RiskScore, RiskLevel, RiskFlag, SentinelError, BehaviorConfig};
use std::sync::Arc;

pub use agent_profile::{AgentProfiler, AgentBehavior};
pub use anomaly::{AnomalyDetector, AnomalyType};
pub use coordination::{CoordinationDetector, CoordinatedAttack};
pub use session::{SessionAnalyzer, SessionRisk};

/// Behavioral Analysis Layer
pub struct BehavioralAnalysis {
    config: BehaviorConfig,
    profiler: Arc<AgentProfiler>,
    anomaly_detector: Arc<AnomalyDetector>,
    coordination_detector: Arc<CoordinationDetector>,
    session_analyzer: Arc<SessionAnalyzer>,
}

impl BehavioralAnalysis {
    /// Create new behavioral analysis layer
    pub fn new(config: BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            profiler: Arc::new(AgentProfiler::new(&config)?),
            anomaly_detector: Arc::new(AnomalyDetector::new(&config)?),
            coordination_detector: Arc::new(CoordinationDetector::new(&config)?),
            session_analyzer: Arc::new(SessionAnalyzer::new(&config)?),
            config,
        })
    }

    /// Analyze request behavior
    /// Target latency: < 10ms
    pub async fn analyze(
        &self,
        request: &Request,
        agent_id: Option<&AgentId>,
    ) -> Result<RiskScore, SentinelError> {
        let mut score = RiskScore::default();

        // 1. Session analysis (always)
        let session_risk = self.session_analyzer.analyze(request).await?;
        score.behavioral_score += session_risk.score * 0.3;

        if session_risk.is_suspicious {
            score.add_flag(RiskFlag::SuspiciousSession);
        }

        // 2. Agent profiling (if authenticated)
        if let Some(agent_id) = agent_id {
            let behavior = self.profiler.analyze(agent_id, request).await?;

            if behavior.is_anomalous {
                score.add_flag(RiskFlag::BehaviorAnomaly);
                score.behavioral_score += 0.4;
            }

            // Check velocity (too many requests too fast)
            if behavior.velocity_exceeded {
                score.add_flag(RiskFlag::VelocityExceeded);
                score.behavioral_score += 0.3;
            }

            // Check pattern deviation
            if behavior.pattern_deviation > self.config.deviation_threshold {
                score.add_flag(RiskFlag::PatternDeviation);
                score.behavioral_score += behavior.pattern_deviation * 0.5;
            }
        }

        // 3. Anomaly detection (ML-based)
        if self.config.enable_ml_anomaly {
            let anomalies = self.anomaly_detector.detect(request).await?;
            for anomaly in &anomalies {
                match anomaly {
                    AnomalyType::StatisticalOutlier => {
                        score.add_flag(RiskFlag::StatisticalAnomaly);
                        score.behavioral_score += 0.3;
                    }
                    AnomalyType::TemporalAnomaly => {
                        score.add_flag(RiskFlag::TemporalAnomaly);
                        score.behavioral_score += 0.4;
                    }
                    AnomalyType::SequenceAnomaly => {
                        score.add_flag(RiskFlag::SequenceAnomaly);
                        score.behavioral_score += 0.5;
                    }
                }
            }
        }

        // 4. Coordinated attack detection
        if self.config.enable_coordination_detection {
            if let Some(attack) = self.coordination_detector.detect(request).await? {
                match attack {
                    CoordinatedAttack::BotNet => {
                        score.add_flag(RiskFlag::CoordinatedBotnet);
                        score.behavioral_score += 0.9;
                    }
                    CoordinatedAttack::DistributedProbing => {
                        score.add_flag(RiskFlag::DistributedProbing);
                        score.behavioral_score += 0.7;
                    }
                    CoordinatedAttack::SybilAttack => {
                        score.add_flag(RiskFlag::SybilAttack);
                        score.behavioral_score += 0.8;
                    }
                }
            }
        }

        // Normalize score
        score.behavioral_score = score.behavioral_score.min(1.0);

        // Set risk level based on behavioral score
        score.level = if score.behavioral_score >= 0.8 {
            RiskLevel::Critical
        } else if score.behavioral_score >= 0.6 {
            RiskLevel::High
        } else if score.behavioral_score >= 0.4 {
            RiskLevel::Medium
        } else if score.behavioral_score >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        Ok(score)
    }

    /// Record a request for learning
    pub async fn record(&self, request: &Request, agent_id: Option<&AgentId>) -> Result<(), SentinelError> {
        // Record for coordination detection
        self.coordination_detector.record(request).await;

        // Record for session analysis
        self.session_analyzer.record(request).await;

        // Record for agent profiling
        if let Some(agent_id) = agent_id {
            self.profiler.record(agent_id, request).await?;
        }

        Ok(())
    }

    /// Get agent profile
    pub async fn get_profile(&self, agent_id: &AgentId) -> Option<AgentBehavior> {
        self.profiler.get_profile(agent_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_behavioral_analysis_creation() {
        let config = BehaviorConfig::default();
        let analysis = BehavioralAnalysis::new(config);
        assert!(analysis.is_ok());
    }
}
