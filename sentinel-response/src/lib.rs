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
use sentinel_persistence::PortalClient;
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
    /// Create new response layer (NO persistence — legacy log-only).
    pub fn new(config: ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            action_engine: Arc::new(ActionEngine::new(&config)?),
            challenge_generator: Arc::new(ChallengeGenerator::new(&config)?),
            ban_manager: Arc::new(BanManager::new(&config)?),
            escalation_manager: Arc::new(EscalationManager::new(&config)?),
            config,
        })
    }

    /// Create new response layer con persistenza Portal API.
    /// I ban generati da `determine_action` / `ban_ip` saranno replicati
    /// in PostgreSQL via POST /api/v1/internal/sentinel/ban.
    pub fn with_persistence(
        config: ResponseConfig,
        persistence: PortalClient,
    ) -> Result<Self, SentinelError> {
        Ok(Self {
            action_engine: Arc::new(ActionEngine::new(&config)?),
            challenge_generator: Arc::new(ChallengeGenerator::new(&config)?),
            ban_manager: Arc::new(BanManager::with_persistence(&config, persistence)?),
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
        // Vettore RAW 18-feature (costruito dal server, che ha Request+geo+neural) →
        // allegato alla riga security_threats sul ban Critical, per il training. None ⇒
        // nessuna cattura (es. chiamate senza contesto). Opaco qui (response non ha neural).
        ml_features: Option<serde_json::Value>,
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

        // Determine action based on risk level.
        let is_llm_prompt = request.category.as_deref() == Some("llm_prompt");
        let action = match risk_score.level {
            // Traffico LLM interno autenticato (AI scaffold): i prompt legittimi
            // contengono codice/JSON dei workflow, che il content classifier
            // flaggerebbe Critical (falso positivo). NON bannare e NON bloccare —
            // solo log advisory. La protezione resta a monte (license + quota nel
            // gateway) e sull'IP-reputation (che non scatta su 0.0.0.0/trusted,
            // is_unbannable). Vedi incident 2026-06-06.
            RiskLevel::Critical if is_llm_prompt => {
                tracing::warn!(
                    ip = %request.client_ip,
                    level = ?risk_score.level,
                    "llm_prompt Critical → Allow (content classifier advisory, no ban/block)"
                );
                Action::Allow
            }
            RiskLevel::Critical => {
                // Escalate SEMPRE (alert al team = indipendente dal blocco).
                self.escalation_manager
                    .escalate(EscalationLevel::Critical, request, risk_score)
                    .await?;

                // `auto_block_enabled` ora ONORATO (era ignorato → config che mentiva): se
                // l'operatore disattiva l'auto-block, modalità monitor-only (escalato, NON
                // bannato/bloccato). Default true → comportamento invariato.
                if self.config.auto_block_enabled {
                    self.ban_manager
                        .ban_ip_with_features(request.client_ip, BanReason::CriticalRisk, self.config.critical_ban_duration, ml_features)
                        .await;
                    if let Some(agent_id) = agent_id {
                        self.ban_manager
                            .ban_agent(agent_id.clone(), BanReason::CriticalRisk, self.config.critical_ban_duration)
                            .await;
                    }
                    Action::Block {
                        reason: "Security threat detected".to_string(),
                        retry_after: Some(self.config.critical_ban_duration),
                    }
                } else {
                    tracing::warn!(
                        ip = %request.client_ip,
                        "Critical ma auto_block_enabled=false → monitor-only (escalato, NON bannato)"
                    );
                    Action::Allow
                }
            }

            RiskLevel::High => {
                // Escalate to monitoring
                self.escalation_manager
                    .escalate(EscalationLevel::High, request, risk_score)
                    .await?;

                // `challenges_enabled` ora ONORATO: se disattivato, fallback a rate-limit
                // (era ignorato → la challenge partiva comunque).
                if self.config.challenges_enabled {
                    let challenge = self.challenge_generator
                        .generate(ChallengeType::ProofOfWork, risk_score)
                        .await?;
                    Action::Challenge(challenge)
                } else {
                    Action::RateLimit { requests_per_minute: self.config.low_rate_limit }
                }
            }

            RiskLevel::Medium => {
                // Soft challenge (se abilitate E almeno 2 flag) o rate limit.
                if self.config.challenges_enabled && risk_score.flags.len() >= 2 {
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

    /// Registra un campione benigno (classe negativa per il training). Delega al BanManager
    /// (che ha la persistence). No-op senza persistence. Vedi process() benign-sampling.
    pub fn record_benign_sample(&self, ml_features: serde_json::Value) {
        self.ban_manager.record_benign_sample(ml_features);
    }

    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, SentinelError> {
        self.challenge_generator.verify(challenge_id, response).await
    }

    /// G21.1: registra l'observer dei ban sul BanManager sottostante.
    /// Punto di convergenza di TUTTI i ban (determine_action CriticalRisk
    /// incluso). Set-once: ritorna false se già registrato.
    pub fn set_ban_notifier(&self, notifier: bans::BanNotifier) -> bool {
        self.ban_manager.set_ban_notifier(notifier)
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

    /// Come `ban_ip`, ma allega il vettore RAW 18-feature alla riga
    /// `security_threats` (training del threat_classifier — Fase ML 2026-07-07:
    /// usato dal path honeypot, che è ~90% dei threat persistiti).
    pub async fn ban_ip_with_features(
        &self,
        ip: std::net::IpAddr,
        reason: BanReason,
        duration: std::time::Duration,
        ml_features: Option<serde_json::Value>,
    ) {
        self.ban_manager.ban_ip_with_features(ip, reason, duration, ml_features).await;
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

    /// Get all banned IPs (for sync API)
    pub fn get_banned_ips(&self) -> Vec<(std::net::IpAddr, BanEntry)> {
        self.ban_manager.get_banned_ips()
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

        let action = layer.determine_action(&request, &risk_score, None, None).await.unwrap();
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

        let action = layer.determine_action(&request, &risk_score, None, None).await.unwrap();
        assert!(matches!(action, Action::Block { .. }));
    }

    #[tokio::test]
    async fn test_llm_prompt_critical_not_blocked() {
        let config = ResponseConfig::default();
        let layer = ResponseLayer::new(config).unwrap();

        // Stesso risk Critical, MA category "llm_prompt" → declassato ad Allow
        // (content classifier advisory, no ban/block). Vedi incident 2026-06-06:
        // i prompt AI-scaffold legittimi (codice/JSON) venivano flaggati Critical.
        let request = Request { category: Some("llm_prompt".to_string()), ..Default::default() };
        let risk_score = RiskScore { level: RiskLevel::Critical, ..Default::default() };

        let action = layer.determine_action(&request, &risk_score, None, None).await.unwrap();
        assert!(matches!(action, Action::Allow), "llm_prompt Critical deve essere Allow, non Block");
    }

    // ── Config ONORATA (era ignorata: i flag non venivano mai letti) ─────────────
    #[tokio::test]
    async fn test_critical_monitor_only_when_auto_block_disabled() {
        // auto_block_enabled=false → Critical NON deve bannare/bloccare (monitor-only).
        // Mutation-check: senza il wiring del flag questo tornerebbe Block → rosso.
        let config = ResponseConfig { auto_block_enabled: false, ..ResponseConfig::default() };
        let layer = ResponseLayer::new(config).unwrap();
        let risk_score = RiskScore { level: RiskLevel::Critical, ..Default::default() };

        let action = layer.determine_action(&Request::default(), &risk_score, None, None).await.unwrap();
        assert!(matches!(action, Action::Allow), "auto_block_enabled=false deve dare Allow (monitor-only), non Block");
    }

    #[tokio::test]
    async fn test_high_falls_back_to_ratelimit_when_challenges_disabled() {
        // challenges_enabled=false → High NON deve emettere challenge → fallback RateLimit.
        let config = ResponseConfig { challenges_enabled: false, ..ResponseConfig::default() };
        let layer = ResponseLayer::new(config).unwrap();
        let risk_score = RiskScore { level: RiskLevel::High, ..Default::default() };

        let action = layer.determine_action(&Request::default(), &risk_score, None, None).await.unwrap();
        assert!(matches!(action, Action::RateLimit { .. }), "challenges_enabled=false deve dare RateLimit, non Challenge");
    }

    #[tokio::test]
    async fn test_critical_blocks_by_default() {
        // Difesa: col default (auto_block_enabled=true) il Critical DEVE bloccare (no regressione).
        let layer = ResponseLayer::new(ResponseConfig::default()).unwrap();
        let risk_score = RiskScore { level: RiskLevel::Critical, ..Default::default() };
        let action = layer.determine_action(&Request::default(), &risk_score, None, None).await.unwrap();
        assert!(matches!(action, Action::Block { .. }), "default deve bloccare il Critical");
    }
}
