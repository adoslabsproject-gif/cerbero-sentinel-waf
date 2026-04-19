// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! SENTINEL Response Layer - Layer 4
//!
//! Adaptive response and enforcement:
//! - Action determination based on risk
//! - Challenge generation (CAPTCHA, proof-of-work)
//! - Ban management
//! - Alert escalation

pub mod actions;
pub mod challenges;
pub mod bans;
pub mod escalation;

use sentinel_core::{
    AgentId, Request, LayerRiskScore as RiskScore, RiskLevel, SentinelError, ResponseConfig,
    Action, ChallengeType
};
use std::sync::Arc;

pub use actions::{ActionEngine, ActionResult};
pub use challenges::{ChallengeGenerator, ChallengeVerifier};
pub use bans::{BanManager, BanEntry, BanReason};
pub use escalation::{EscalationManager, EscalationLevel};

/// Response Layer - Adaptive enforcement
pub struct ResponseLayer {
    config: ResponseConfig,
    action_engine: Arc<ActionEngine>,
    challenge_generator: Arc<ChallengeGenerator>,
    ban_manager: Arc<BanManager>,
    escalation_manager: Arc<EscalationManager>,
}

impl ResponseLayer {
    /// Create new response layer
    pub fn new(config: ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            action_engine: Arc::new(ActionEngine::new(&config)?),
            challenge_generator: Arc::new(ChallengeGenerator::new(&config)?),
            ban_manager: Arc::new(BanManager::new(&config)?),
            escalation_manager: Arc::new(EscalationManager::new(&config)?),
            config,
        })
    }

    /// Determine response action based on risk score
    pub async fn determine_action(
        &self,
        request: &Request,
        risk_score: &RiskScore,
        agent_id: Option<&AgentId>,
    ) -> Result<Action, SentinelError> {
        // Check for existing ban
        if self.ban_manager.is_banned(&request.client_ip).await {
            return Ok(Action::Block {
                reason: "IP banned".to_string(),
                retry_after: Some(self.ban_manager.time_until_unban(&request.client_ip).await),
            });
        }

        if let Some(agent_id) = agent_id {
            if self.ban_manager.is_agent_banned(agent_id).await {
                return Ok(Action::Block {
                    reason: "Agent banned".to_string(),
                    retry_after: Some(self.ban_manager.time_until_agent_unban(agent_id).await),
                });
            }
        }

        // Determine action based on risk level
        let action = match risk_score.level {
            RiskLevel::Critical => {
                // Auto-ban and block
                self.ban_manager
                    .ban_ip(request.client_ip, BanReason::CriticalRisk, self.config.critical_ban_duration)
                    .await;

                if let Some(agent_id) = agent_id {
                    self.ban_manager
                        .ban_agent(agent_id.clone(), BanReason::CriticalRisk, self.config.critical_ban_duration)
                        .await;
                }

                // Escalate to security team
                self.escalation_manager
                    .escalate(EscalationLevel::Critical, request, risk_score)
                    .await?;

                Action::Block {
                    reason: "Security threat detected".to_string(),
                    retry_after: Some(self.config.critical_ban_duration),
                }
            }

            RiskLevel::High => {
                // Challenge required
                let challenge = self.challenge_generator
                    .generate(ChallengeType::ProofOfWork, risk_score)
                    .await?;

                // Escalate to monitoring
                self.escalation_manager
                    .escalate(EscalationLevel::High, request, risk_score)
                    .await?;

                Action::Challenge(challenge)
            }

            RiskLevel::Medium => {
                // Soft challenge or rate limit
                if risk_score.flags.len() >= 2 {
                    let challenge = self.challenge_generator
                        .generate(ChallengeType::Interactive, risk_score)
                        .await?;
                    Action::Challenge(challenge)
                } else {
                    Action::RateLimit {
                        requests_per_minute: self.config.medium_rate_limit,
                    }
                }
            }

            RiskLevel::Low => {
                // Just rate limit
                Action::RateLimit {
                    requests_per_minute: self.config.low_rate_limit,
                }
            }

            RiskLevel::None => {
                // Allow with normal rate limits
                Action::Allow
            }
        };

        // Record action for learning
        self.action_engine.record_action(request, &action, risk_score).await;

        Ok(action)
    }

    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, SentinelError> {
        self.challenge_generator.verify(challenge_id, response).await
    }

    /// Manually ban an IP
    pub async fn ban_ip(
        &self,
        ip: std::net::IpAddr,
        reason: BanReason,
        duration: std::time::Duration,
    ) {
        self.ban_manager.ban_ip(ip, reason, duration).await;
    }

    /// Manually ban an agent
    pub async fn ban_agent(
        &self,
        agent_id: AgentId,
        reason: BanReason,
        duration: std::time::Duration,
    ) {
        self.ban_manager.ban_agent(agent_id, reason, duration).await;
    }

    /// Unban an IP
    pub async fn unban_ip(&self, ip: std::net::IpAddr) {
        self.ban_manager.unban_ip(&ip).await;
    }

    /// Get ban info
    pub async fn get_ban_info(&self, ip: std::net::IpAddr) -> Option<BanEntry> {
        self.ban_manager.get_ban_info(&ip).await
    }

    /// Get stats
    pub fn get_stats(&self) -> ResponseStats {
        ResponseStats {
            active_bans: self.ban_manager.active_ban_count(),
            pending_challenges: self.challenge_generator.pending_count(),
            escalations_today: self.escalation_manager.today_count(),
        }
    }
}

/// Response layer statistics
#[derive(Debug, Clone)]
pub struct ResponseStats {
    /// Number of active bans
    pub active_bans: usize,
    /// Number of pending challenges
    pub pending_challenges: usize,
    /// Number of escalations today
    pub escalations_today: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_response_layer_creation() {
        let config = ResponseConfig::default();
        let layer = ResponseLayer::new(config);
        assert!(layer.is_ok());
    }

    #[tokio::test]
    async fn test_allow_clean_request() {
        let config = ResponseConfig::default();
        let layer = ResponseLayer::new(config).unwrap();

        let request = Request::default();
        let risk_score = RiskScore::default();

        let action = layer.determine_action(&request, &risk_score, None).await.unwrap();
        assert!(matches!(action, Action::Allow));
    }

    #[tokio::test]
    async fn test_block_critical_risk() {
        let config = ResponseConfig::default();
        let layer = ResponseLayer::new(config).unwrap();

        let request = Request::default();
        let risk_score = RiskScore {
            level: RiskLevel::Critical,
            ..Default::default()
        };

        let action = layer.determine_action(&request, &risk_score, None).await.unwrap();
        assert!(matches!(action, Action::Block { .. }));
    }
}
