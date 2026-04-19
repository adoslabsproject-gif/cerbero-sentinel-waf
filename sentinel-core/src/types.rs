//! Common types used across SENTINEL modules

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for SENTINEL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Edge layer configuration
    pub edge: EdgeConfig,

    /// Neural layer configuration
    pub neural: NeuralConfig,

    /// Behavioral layer configuration
    pub behavior: crate::config::BehaviorConfig,

    /// Response layer configuration
    pub response: ResponseConfig,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            edge: EdgeConfig::default(),
            neural: NeuralConfig::default(),
            behavior: crate::config::BehaviorConfig::default(),
            response: ResponseConfig::default(),
        }
    }
}

/// Edge layer (Layer 1) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Enable rate limiting
    pub rate_limiting_enabled: bool,

    /// Enable IP reputation checks
    pub ip_reputation_enabled: bool,

    /// Enable Tor exit node detection
    pub block_tor: bool,

    /// Enable proxy/VPN detection
    pub block_proxies: bool,

    /// Default rate limit (requests per minute)
    pub default_rate_limit: u32,

    /// Rate limit window in seconds
    pub rate_limit_window: u64,

    /// IP reputation cache TTL
    #[serde(with = "humantime_serde")]
    pub ip_cache_ttl: Duration,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            rate_limiting_enabled: true,
            ip_reputation_enabled: true,
            block_tor: false, // Don't block by default
            block_proxies: false,
            default_rate_limit: 60,
            rate_limit_window: 60,
            ip_cache_ttl: Duration::from_secs(300),
        }
    }
}

/// Neural layer (Layer 2) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralConfig {
    /// Enable prompt injection detection
    pub prompt_injection_enabled: bool,

    /// Prompt injection detection threshold (0.0 - 1.0)
    pub prompt_injection_threshold: f32,

    /// Enable semantic content analysis
    pub semantic_analysis_enabled: bool,

    /// Enable toxicity detection
    pub toxicity_detection_enabled: bool,

    /// Toxicity threshold
    pub toxicity_threshold: f32,

    /// Path to ONNX models directory
    pub models_path: String,

    /// Maximum text length for analysis
    pub max_text_length: usize,

    /// Batch size for inference
    pub inference_batch_size: usize,

    /// Enable ML-based detection (vs regex only)
    pub enable_ml_detection: bool,

    /// Injection detection threshold (0.0 - 1.0)
    pub injection_threshold: f64,

    /// Enable toxicity check
    pub enable_toxicity_check: bool,

    /// Toxicity threshold (f64 version)
    pub toxicity_threshold_f64: f64,

    /// Enable LLM output safety check
    pub enable_llm_output_safety: bool,

    /// LLM output safety threshold (0.0 - 1.0)
    pub llm_output_safety_threshold: f64,
}

impl Default for NeuralConfig {
    fn default() -> Self {
        Self {
            prompt_injection_enabled: true,
            prompt_injection_threshold: 0.7,
            semantic_analysis_enabled: true,
            toxicity_detection_enabled: true,
            toxicity_threshold: 0.7,
            models_path: "./ml/models".to_string(),
            max_text_length: 8192,
            inference_batch_size: 8,
            enable_ml_detection: true,
            injection_threshold: 0.7,
            enable_toxicity_check: true,
            toxicity_threshold_f64: 0.7,
            enable_llm_output_safety: true,
            llm_output_safety_threshold: 0.80,
        }
    }
}

/// Response layer (Layer 4) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Enable automatic blocking
    pub auto_block_enabled: bool,

    /// Default block duration
    #[serde(with = "humantime_serde")]
    pub default_block_duration: Duration,

    /// Enable challenges
    pub challenges_enabled: bool,

    /// Proof of work difficulty (leading zeros)
    pub pow_difficulty: u32,

    /// Challenge expiry time
    #[serde(with = "humantime_serde")]
    pub challenge_expiry: Duration,

    /// Enable incident auto-creation
    pub auto_incident_creation: bool,

    /// Ban duration for critical risks
    #[serde(with = "humantime_serde")]
    pub critical_ban_duration: Duration,

    /// Rate limit for medium risk
    pub medium_rate_limit: u32,

    /// Rate limit for low risk
    pub low_rate_limit: u32,

    /// Challenge expiration in seconds
    pub challenge_expiration_secs: u64,

    /// Max challenge attempts
    pub max_challenge_attempts: u8,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_block_enabled: true,
            default_block_duration: Duration::from_secs(3600),
            challenges_enabled: true,
            pow_difficulty: 16, // 16 leading zero bits
            challenge_expiry: Duration::from_secs(60),
            auto_incident_creation: true,
            critical_ban_duration: Duration::from_secs(86400), // 24 hours
            medium_rate_limit: 30,
            low_rate_limit: 60,
            challenge_expiration_secs: 300,
            max_challenge_attempts: 3,
        }
    }
}

/// Weights for risk score aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskWeights {
    pub ip_reputation: f32,
    pub rate_limit_pressure: f32,
    pub prompt_injection: f32,
    pub content_toxicity: f32,
    pub behavioral_anomaly: f32,
    pub style_drift: f32,
    pub coordinated_attack: f32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        Self {
            ip_reputation: 0.15,
            rate_limit_pressure: 0.10,
            prompt_injection: 0.25,
            content_toxicity: 0.15,
            behavioral_anomaly: 0.20,
            style_drift: 0.10,
            coordinated_attack: 0.05,
        }
    }
}

// Custom serde module for Duration
mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}
