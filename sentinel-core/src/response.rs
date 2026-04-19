//! Response types for SENTINEL enforcement

use crate::risk::{ChallengeType, UnifiedRiskScore};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of SENTINEL enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum EnforcementResult {
    /// Request is allowed
    Allow {
        /// Risk assessment (for logging)
        risk: UnifiedRiskScore,
    },

    /// Request allowed with rate limiting applied
    RateLimited {
        /// Risk assessment
        risk: UnifiedRiskScore,
        /// New rate limit factor (0.0 - 1.0)
        limit_factor: f32,
        /// Requests remaining
        remaining: u32,
        /// Reset time
        reset_at: chrono::DateTime<chrono::Utc>,
    },

    /// Challenge required before proceeding
    ChallengeRequired {
        /// Risk assessment
        risk: UnifiedRiskScore,
        /// Challenge details
        challenge: Challenge,
    },

    /// Request is blocked
    Blocked {
        /// Risk assessment
        risk: UnifiedRiskScore,
        /// Reason for blocking
        reason: String,
        /// How long the block lasts
        duration: Option<Duration>,
        /// When the block expires
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    },
}

impl EnforcementResult {
    /// Check if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. } | Self::RateLimited { .. })
    }

    /// Get the HTTP status code for this result
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Allow { .. } => 200,
            Self::RateLimited { .. } => 200, // Still allowed, just limited
            Self::ChallengeRequired { .. } => 428, // Precondition Required
            Self::Blocked { .. } => 403,
        }
    }

    /// Get the risk score
    pub fn risk_score(&self) -> f32 {
        match self {
            Self::Allow { risk } => risk.score,
            Self::RateLimited { risk, .. } => risk.score,
            Self::ChallengeRequired { risk, .. } => risk.score,
            Self::Blocked { risk, .. } => risk.score,
        }
    }
}

/// Challenge to be solved by the client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: String,

    /// Type of challenge
    pub challenge_type: ChallengeType,

    /// Challenge data (depends on type)
    pub data: ChallengeData,

    /// When the challenge expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Challenge-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChallengeData {
    /// Proof of work challenge
    ProofOfWork {
        /// Nonce to include in hash
        nonce: String,
        /// Number of leading zeros required
        difficulty: u32,
        /// Hash algorithm to use
        algorithm: String,
    },

    /// Rate delay challenge
    RateDelay {
        /// Token to return after delay
        token: String,
        /// Required delay in seconds
        delay_seconds: u64,
    },

    /// Signature verification challenge
    SignatureVerification {
        /// Message to sign
        message: String,
        /// Expected public key (for verification)
        expected_key_id: String,
    },
}

/// Solution to a challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSolution {
    /// Challenge ID being solved
    pub challenge_id: String,

    /// Solution data
    pub solution: SolutionData,
}

/// Solution-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SolutionData {
    /// Proof of work solution
    ProofOfWork {
        /// The nonce that produces valid hash
        solution_nonce: String,
    },

    /// Rate delay solution
    RateDelay {
        /// Token returned after waiting
        token: String,
    },

    /// Signature verification solution
    SignatureVerification {
        /// Signature of the message
        signature: String,
    },
}

/// HTTP response to send back
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// HTTP status code
    pub status: u16,

    /// Response headers to add
    pub headers: Vec<(String, String)>,

    /// Response body (JSON)
    pub body: serde_json::Value,
}

impl Response {
    /// Create a response from enforcement result
    pub fn from_enforcement(result: &EnforcementResult, request_id: &str) -> Self {
        let status = result.status_code();

        let mut headers = vec![
            ("X-Request-ID".to_string(), request_id.to_string()),
            (
                "X-Risk-Score".to_string(),
                format!("{:.3}", result.risk_score()),
            ),
        ];

        let body = match result {
            EnforcementResult::Allow { .. } => {
                // No body modification needed
                serde_json::json!({})
            }

            EnforcementResult::RateLimited {
                limit_factor,
                remaining,
                reset_at,
                ..
            } => {
                headers.push((
                    "X-RateLimit-Limit".to_string(),
                    format!("{:.0}", limit_factor * 100.0),
                ));
                headers.push(("X-RateLimit-Remaining".to_string(), remaining.to_string()));
                headers.push((
                    "X-RateLimit-Reset".to_string(),
                    reset_at.timestamp().to_string(),
                ));
                serde_json::json!({})
            }

            EnforcementResult::ChallengeRequired { challenge, .. } => {
                headers.push(("Retry-After".to_string(), "60".to_string()));
                serde_json::json!({
                    "error": {
                        "code": "CHALLENGE_REQUIRED",
                        "message": "Security challenge required",
                        "challenge": challenge
                    }
                })
            }

            EnforcementResult::Blocked {
                reason,
                expires_at,
                ..
            } => {
                if let Some(expires) = expires_at {
                    let retry_after = (expires.timestamp() - chrono::Utc::now().timestamp()).max(0);
                    headers.push(("Retry-After".to_string(), retry_after.to_string()));
                }
                serde_json::json!({
                    "error": {
                        "code": "BLOCKED",
                        "message": reason
                    }
                })
            }
        };

        Self {
            status,
            headers,
            body,
        }
    }
}
