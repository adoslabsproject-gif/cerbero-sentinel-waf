// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! SENTINEL Edge Shield - Layer 1
//!
//! Provides edge-level protection:
//! - Adaptive rate limiting with sliding window
//! - IP reputation and threat intelligence
//! - DDoS detection and mitigation
//! - Geographic restrictions

pub mod rate_limiter;
pub mod ip_intel;
pub mod ddos;
pub mod ban_store;
pub mod honeypot;

use sentinel_core::{Request, LayerRiskScore as RiskScore, RiskLevel, RiskFlag, SentinelError, EdgeConfig};
use std::sync::Arc;
use std::net::IpAddr;

pub use rate_limiter::{RateLimiter, RateLimitResult};
pub use ip_intel::{IpIntelligence, IpReputation, ThreatType};
pub use ddos::{DDoSDetector, DDoSPattern};
pub use ban_store::{BanStore, BanStoreConfig, BanEntry};
pub use honeypot::{HoneypotDetector, HoneypotHit};

/// Edge Shield - First line of defense
pub struct EdgeShield {
    config: EdgeConfig,
    rate_limiter: Arc<RateLimiter>,
    ip_intel: Arc<IpIntelligence>,
    ddos_detector: Arc<DDoSDetector>,
}

impl EdgeShield {
    /// Create a new Edge Shield with the given configuration
    pub fn new(config: EdgeConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_window,
                config.default_rate_limit as u64,
            )),
            ip_intel: Arc::new(IpIntelligence::new()),
            ddos_detector: Arc::new(DDoSDetector::new()),
            config,
        })
    }

    /// Analyze a request and return a risk score
    /// Target latency: < 1ms
    pub async fn analyze(&self, request: &Request) -> Result<RiskScore, SentinelError> {
        let mut score = RiskScore::default();
        let ip = request.client_ip;

        // 1. Check rate limit
        if self.config.rate_limiting_enabled {
            let rate_result = self.rate_limiter.check(ip).await;
            if rate_result.is_limited {
                score.add_flag(RiskFlag::HighVolume);
                score.edge_score += 0.8;
            } else if rate_result.usage_ratio > 0.7 {
                score.edge_score += rate_result.usage_ratio * 0.3;
            }
        }

        // 2. Check IP reputation
        if self.config.ip_reputation_enabled {
            let reputation = self.ip_intel.check(ip).await;
            match reputation.threat_type {
                Some(ThreatType::KnownAttacker) => {
                    score.add_flag(RiskFlag::KnownAttacker);
                    score.edge_score += 0.9;
                }
                Some(ThreatType::TorExitNode) => {
                    if self.config.block_tor {
                        score.add_flag(RiskFlag::TorExit);
                        score.edge_score += 0.6;
                    } else {
                        score.add_flag(RiskFlag::TorExit);
                        score.edge_score += 0.2;
                    }
                }
                Some(ThreatType::Proxy) => {
                    if self.config.block_proxies {
                        score.add_flag(RiskFlag::Proxy);
                        score.edge_score += 0.5;
                    } else {
                        score.add_flag(RiskFlag::Proxy);
                        score.edge_score += 0.1;
                    }
                }
                Some(ThreatType::Scanner) => {
                    score.add_flag(RiskFlag::Scanner);
                    score.edge_score += 0.7;
                }
                Some(ThreatType::Botnet) => {
                    score.add_flag(RiskFlag::Botnet);
                    score.edge_score += 0.95;
                }
                None => {}
            }

            // Add reputation score
            score.edge_score += (1.0 - reputation.score) * 0.2;
        }

        // 3. Check for DDoS patterns
        if let Some(pattern) = self.ddos_detector.check(ip, request).await {
            match pattern {
                DDoSPattern::Volumetric => {
                    score.add_flag(RiskFlag::HighVolume);
                    score.edge_score += 0.85;
                }
                DDoSPattern::SlowLoris => {
                    score.add_flag(RiskFlag::TimingAnomaly);
                    score.edge_score += 0.75;
                }
                DDoSPattern::ApplicationLayer => {
                    score.add_flag(RiskFlag::AnomalousPattern);
                    score.edge_score += 0.8;
                }
            }
        }

        // Normalize score
        score.edge_score = score.edge_score.min(1.0);

        // Set risk level based on edge score
        score.level = if score.edge_score >= 0.8 {
            RiskLevel::Critical
        } else if score.edge_score >= 0.6 {
            RiskLevel::High
        } else if score.edge_score >= 0.4 {
            RiskLevel::Medium
        } else if score.edge_score >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        Ok(score)
    }

    /// Block an IP address
    pub async fn block_ip(&self, ip: IpAddr, reason: &str, duration_secs: u64) {
        self.ip_intel.block(ip, reason, duration_secs).await;
    }

    /// Unblock an IP address
    pub async fn unblock_ip(&self, ip: IpAddr) {
        self.ip_intel.unblock(ip).await;
    }

    /// Get current rate limit status for an IP
    pub async fn get_rate_limit_status(&self, ip: IpAddr) -> RateLimitResult {
        self.rate_limiter.check(ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_edge_shield_creation() {
        let config = EdgeConfig::default();
        let shield = EdgeShield::new(config).unwrap();
        assert!(Arc::strong_count(&shield.rate_limiter) == 1);
    }

    #[tokio::test]
    async fn test_clean_request() {
        let config = EdgeConfig::default();
        let shield = EdgeShield::new(config).unwrap();

        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            ..Default::default()
        };

        let score = shield.analyze(&request).await.unwrap();
        assert!(score.edge_score < 0.2);
        assert_eq!(score.level, RiskLevel::None);
    }
}
