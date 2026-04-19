//! Behavioral layer configuration

use serde::{Deserialize, Serialize};


/// Behavioral layer (Layer 3) configuration - Extended
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    /// Enable ML-based anomaly detection
    pub enable_ml_anomaly: bool,

    /// Enable coordination detection
    pub enable_coordination_detection: bool,

    /// Profile window in seconds
    pub profile_window_secs: u64,

    /// Maximum requests per window
    pub max_requests_per_window: usize,

    /// Deviation threshold for pattern analysis
    pub deviation_threshold: f64,

    /// Z-score threshold for anomaly detection
    pub anomaly_z_threshold: f64,

    /// Coordination window in seconds
    pub coordination_window_secs: u64,

    /// IP threshold for botnet detection
    pub botnet_ip_threshold: usize,

    /// Rate threshold for botnet detection
    pub botnet_rate_threshold: f64,

    /// IP threshold for probing detection
    pub probing_ip_threshold: usize,

    /// Signature threshold for Sybil detection
    pub sybil_signature_threshold: usize,

    /// Session max age in seconds
    pub session_max_age_secs: u64,

    /// Fingerprint match threshold
    pub fingerprint_match_threshold: f64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            enable_ml_anomaly: true,
            enable_coordination_detection: true,
            profile_window_secs: 3600, // 1 hour
            max_requests_per_window: 1000,
            deviation_threshold: 0.5,
            anomaly_z_threshold: 3.0,
            coordination_window_secs: 300, // 5 minutes
            botnet_ip_threshold: 10,
            botnet_rate_threshold: 10.0,
            probing_ip_threshold: 5,
            sybil_signature_threshold: 20,
            session_max_age_secs: 86400, // 24 hours
            fingerprint_match_threshold: 0.7,
        }
    }
}
