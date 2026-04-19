//! Error types for SENTINEL

use thiserror::Error;

/// Result type alias for SENTINEL operations
pub type SentinelResult<T> = Result<T, SentinelError>;

/// Main error type for SENTINEL
#[derive(Error, Debug)]
pub enum SentinelError {
    /// Rate limit exceeded
    #[error("Rate limit exceeded: {limit} requests per {window_seconds}s")]
    RateLimitExceeded {
        limit: u32,
        window_seconds: u64,
        retry_after: u64,
    },

    /// IP blocked
    #[error("IP address blocked: {reason}")]
    IpBlocked { ip: String, reason: String },

    /// Agent blocked
    #[error("Agent blocked: {reason}")]
    AgentBlocked { agent_id: String, reason: String },

    /// Prompt injection detected
    #[error("Prompt injection detected with {confidence:.2}% confidence")]
    PromptInjectionDetected {
        confidence: f32,
        injection_type: String,
    },

    /// Content policy violation
    #[error("Content policy violation: {violation_type}")]
    ContentPolicyViolation {
        violation_type: String,
        details: String,
    },

    /// Behavioral anomaly
    #[error("Behavioral anomaly detected: {anomaly_type}")]
    BehavioralAnomaly {
        agent_id: String,
        anomaly_type: String,
        score: f32,
    },

    /// Challenge required
    #[error("Challenge required: {challenge_type}")]
    ChallengeRequired {
        challenge_type: String,
        challenge_data: String,
    },

    /// Model inference error
    #[error("ML model inference failed: {0}")]
    ModelInference(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Challenge not found
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),

    /// Challenge expired
    #[error("Challenge has expired")]
    ChallengeExpired,

    /// Challenge failed
    #[error("Challenge failed: {0}")]
    ChallengeFailed(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl SentinelError {
    /// Returns the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            Self::RateLimitExceeded { .. } => 429,
            Self::IpBlocked { .. } => 403,
            Self::AgentBlocked { .. } => 403,
            Self::PromptInjectionDetected { .. } => 400,
            Self::ContentPolicyViolation { .. } => 400,
            Self::BehavioralAnomaly { .. } => 403,
            Self::ChallengeRequired { .. } => 428, // Precondition Required
            Self::ModelInference(_) => 500,
            Self::Configuration(_) => 500,
            Self::Database(_) => 500,
            Self::Cache(_) => 500,
            Self::Internal(_) => 500,
            Self::ChallengeNotFound(_) => 404,
            Self::ChallengeExpired => 410,
            Self::ChallengeFailed(_) => 400,
            Self::InvalidInput(_) => 400,
        }
    }

    /// Returns the error code for API responses
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::RateLimitExceeded { .. } => "RATE_LIMITED",
            Self::IpBlocked { .. } => "IP_BLOCKED",
            Self::AgentBlocked { .. } => "AGENT_BLOCKED",
            Self::PromptInjectionDetected { .. } => "PROMPT_INJECTION",
            Self::ContentPolicyViolation { .. } => "CONTENT_VIOLATION",
            Self::BehavioralAnomaly { .. } => "BEHAVIORAL_ANOMALY",
            Self::ChallengeRequired { .. } => "CHALLENGE_REQUIRED",
            Self::ModelInference(_) => "MODEL_ERROR",
            Self::Configuration(_) => "CONFIG_ERROR",
            Self::Database(_) => "DB_ERROR",
            Self::Cache(_) => "CACHE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::ChallengeNotFound(_) => "CHALLENGE_NOT_FOUND",
            Self::ChallengeExpired => "CHALLENGE_EXPIRED",
            Self::ChallengeFailed(_) => "CHALLENGE_FAILED",
            Self::InvalidInput(_) => "INVALID_INPUT",
        }
    }

    /// Whether this error should be logged at error level
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            Self::ModelInference(_)
                | Self::Configuration(_)
                | Self::Database(_)
                | Self::Cache(_)
                | Self::Internal(_)
        )
    }
}
