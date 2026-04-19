//! Risk scoring types for SENTINEL

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// No risk detected
    #[default]
    None,
    /// Low risk - monitor only
    Low,
    /// Medium risk - enhanced monitoring
    Medium,
    /// High risk - rate limit reduction
    High,
    /// Critical risk - block or challenge
    Critical,
}

impl RiskLevel {
    /// Create from a score (0.0 - 1.0)
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 0.9 => Self::Critical,
            s if s >= 0.7 => Self::High,
            s if s >= 0.4 => Self::Medium,
            s if s >= 0.1 => Self::Low,
            _ => Self::None,
        }
    }

    /// Get the rate limit multiplier for this risk level
    pub fn rate_limit_multiplier(&self) -> f32 {
        match self {
            Self::None => 1.0,
            Self::Low => 0.9,
            Self::Medium => 0.5,
            Self::High => 0.25,
            Self::Critical => 0.0, // Block
        }
    }
}

/// A single risk score from one analysis component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Source of this score (e.g., "ip_reputation", "prompt_injection")
    pub source: String,
    /// Raw score from the analyzer (0.0 - 1.0)
    pub score: f32,
    /// Weight applied to this score in final calculation
    pub weight: f32,
    /// Confidence in this assessment (0.0 - 1.0)
    pub confidence: f32,
    /// Human-readable explanation
    pub explanation: String,
    /// Additional metadata
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl RiskScore {
    /// Calculate the weighted contribution
    pub fn contribution(&self) -> f32 {
        self.score * self.weight * self.confidence
    }
}

/// Unified risk score combining all analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRiskScore {
    /// Final aggregated score (0.0 - 1.0)
    pub score: f32,
    /// Risk level classification
    pub level: RiskLevel,
    /// Individual scores from each analyzer
    pub components: Vec<RiskScore>,
    /// Recommended action
    pub action: RecommendedAction,
    /// Overall confidence in the assessment
    pub confidence: f32,
    /// Request ID for correlation
    pub request_id: String,
    /// Timestamp of assessment
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl UnifiedRiskScore {
    /// Create a new unified risk score
    pub fn new(request_id: String, components: Vec<RiskScore>) -> Self {
        let (score, confidence) = Self::aggregate(&components);
        let level = RiskLevel::from_score(score);
        let action = RecommendedAction::from_score_and_components(score, &components);

        Self {
            score,
            level,
            components,
            action,
            confidence,
            request_id,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Aggregate component scores into a final score
    fn aggregate(components: &[RiskScore]) -> (f32, f32) {
        if components.is_empty() {
            return (0.0, 0.0);
        }

        let total_weight: f32 = components.iter().map(|c| c.weight).sum();
        if total_weight == 0.0 {
            return (0.0, 0.0);
        }

        let weighted_score: f32 = components.iter().map(|c| c.contribution()).sum();
        let score = (weighted_score / total_weight).clamp(0.0, 1.0);

        // Confidence is weighted average of component confidences
        let weighted_confidence: f32 = components
            .iter()
            .map(|c| c.confidence * c.weight)
            .sum();
        let confidence = (weighted_confidence / total_weight).clamp(0.0, 1.0);

        (score, confidence)
    }

    /// Check if any critical signal was detected
    pub fn has_critical_signal(&self) -> bool {
        self.components.iter().any(|c| {
            c.source == "prompt_injection" && c.score > 0.9
                || c.source == "coordinated_attack" && c.score > 0.8
        })
    }
}

/// Recommended action based on risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Allow the request
    Allow,
    /// Allow but enable enhanced monitoring
    Monitor { enhanced_logging: bool },
    /// Reduce rate limits
    RateLimit { factor: f32 },
    /// Require solving a challenge
    Challenge { challenge_type: ChallengeType },
    /// Block the request
    Block {
        reason: String,
        duration_seconds: Option<u64>,
    },
}

impl RecommendedAction {
    /// Determine action from score and components
    fn from_score_and_components(score: f32, components: &[RiskScore]) -> Self {
        // Check for instant-block conditions
        let has_prompt_injection = components
            .iter()
            .any(|c| c.source == "prompt_injection" && c.score > 0.9);

        if has_prompt_injection {
            return Self::Block {
                reason: "High-confidence prompt injection detected".into(),
                duration_seconds: None,
            };
        }

        let has_coordinated_attack = components
            .iter()
            .any(|c| c.source == "coordinated_attack" && c.score > 0.8);

        if has_coordinated_attack {
            return Self::Block {
                reason: "Coordinated attack pattern detected".into(),
                duration_seconds: Some(3600),
            };
        }

        // Score-based actions
        match score {
            s if s >= 0.9 => Self::Block {
                reason: "Critical risk score".into(),
                duration_seconds: Some(3600),
            },
            s if s >= 0.7 => Self::Challenge {
                challenge_type: ChallengeType::ProofOfWork,
            },
            s if s >= 0.5 => Self::RateLimit { factor: 0.25 },
            s if s >= 0.3 => Self::Monitor {
                enhanced_logging: true,
            },
            _ => Self::Allow,
        }
    }
}

/// Type of challenge to present
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// Proof of work (CPU cost)
    ProofOfWork,
    /// Rate-based delay
    RateDelay,
    /// Cryptographic signature verification
    SignatureVerification,
    /// Interactive challenge
    Interactive,
    /// Token-based challenge
    Token,
}

/// Risk flags that can be attached to assessments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    // IP-related
    KnownAttacker,
    TorExit,
    Proxy,
    Datacenter,
    NewIp,
    Scanner,
    Botnet,

    // Behavioral
    HighVolume,
    AnomalousPattern,
    StyleDrift,
    TimingAnomaly,
    BehaviorAnomaly,
    VelocityExceeded,
    PatternDeviation,
    StatisticalAnomaly,
    TemporalAnomaly,
    SequenceAnomaly,
    SuspiciousSession,

    // Content - Encoding
    Base64Obfuscation,
    UnicodeHomoglyph,
    InvisibleChars,
    ControlChars,
    RtlOverride,

    // Content - Patterns
    SystemPromptLeak,
    JailbreakAttempt,
    PromptLeakage,
    RolePlayExploit,
    InstructionOverride,

    // Content - Injection
    DirectInjection,
    IndirectInjection,
    RecursiveInjection,
    PromptInjection,

    // Content - LLM Output Safety
    MaliciousLLMOutput,

    // Content - Toxicity
    ToxicContent,
    Toxic,
    Spam,
    Manipulation,
    ContainsPii,
    ContainsCredential,

    // Coordination
    CoordinatedActivity,
    BotNetwork,
    CoordinatedBotnet,
    DistributedProbing,
    SybilAttack,
}

/// Simplified RiskScore for layer outputs
#[derive(Debug, Clone, Default)]
pub struct LayerRiskScore {
    /// Risk level
    pub level: RiskLevel,
    /// Edge layer score (0.0 - 1.0)
    pub edge_score: f64,
    /// Neural layer score (0.0 - 1.0)
    pub neural_score: f64,
    /// Behavioral layer score (0.0 - 1.0)
    pub behavioral_score: f64,
    /// Flags detected
    pub flags: Vec<RiskFlag>,
}

impl LayerRiskScore {
    /// Add a flag
    pub fn add_flag(&mut self, flag: RiskFlag) {
        if !self.flags.contains(&flag) {
            self.flags.push(flag);
        }
    }

    /// Calculate total score
    pub fn total_score(&self) -> f64 {
        // Weighted average with neural having highest weight
        let total = self.edge_score * 0.2 + self.neural_score * 0.5 + self.behavioral_score * 0.3;
        total.min(1.0)
    }

    /// Update risk level based on scores
    pub fn update_level(&mut self) {
        let total = self.total_score();
        self.level = if total >= 0.8 {
            RiskLevel::Critical
        } else if total >= 0.6 {
            RiskLevel::High
        } else if total >= 0.4 {
            RiskLevel::Medium
        } else if total >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };
    }
}

// Re-export LayerRiskScore as RiskScore for compatibility
impl RiskScore {
    /// Create default risk score
    pub fn default_layer() -> LayerRiskScore {
        LayerRiskScore::default()
    }
}
