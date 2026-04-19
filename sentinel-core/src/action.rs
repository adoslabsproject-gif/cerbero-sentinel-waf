//! Action types for SENTINEL response layer

use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::risk::ChallengeType;

/// Action to take in response to a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    /// Allow the request
    Allow,

    /// Block the request
    Block {
        /// Reason for blocking
        reason: String,
        /// When to retry (if applicable)
        retry_after: Option<Duration>,
    },

    /// Require a challenge
    Challenge(Challenge),

    /// Apply rate limiting
    RateLimit {
        /// Requests allowed per minute
        requests_per_minute: u32,
    },
}

/// Security challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: String,

    /// Type of challenge
    pub challenge_type: ChallengeType,

    /// Challenge data (varies by type)
    pub data: serde_json::Value,

    /// Time until challenge expires
    pub expires_in: Duration,
}
