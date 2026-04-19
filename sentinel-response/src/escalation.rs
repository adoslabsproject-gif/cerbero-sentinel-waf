//! Escalation Management
//!
//! Handles alert escalation to security teams.

use sentinel_core::{Request, ResponseConfig, LayerRiskScore as RiskScore, SentinelError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Escalation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EscalationLevel {
    /// Low priority - logged only
    Low,
    /// Medium priority - alert to dashboard
    Medium,
    /// High priority - alert to on-call
    High,
    /// Critical - immediate alert to security team
    Critical,
}

/// Escalation event
#[derive(Debug, Clone)]
pub struct EscalationEvent {
    /// Level
    pub level: EscalationLevel,
    /// Client IP
    pub client_ip: String,
    /// Request path
    pub path: String,
    /// Risk score
    pub risk_score: f64,
    /// Risk flags
    pub flags: Vec<String>,
    /// Timestamp
    pub timestamp: Instant,
    /// Human-readable timestamp
    pub timestamp_str: String,
}

/// Escalation manager
pub struct EscalationManager {
    /// Today's escalation count
    today_count: AtomicUsize,
    /// Last reset time
    last_reset: RwLock<Instant>,
    /// Recent escalations
    recent: RwLock<VecDeque<EscalationEvent>>,
    /// Configuration
    #[allow(dead_code)]
    config: ResponseConfig,
}

impl EscalationManager {
    /// Create new escalation manager
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            today_count: AtomicUsize::new(0),
            last_reset: RwLock::new(Instant::now()),
            recent: RwLock::new(VecDeque::with_capacity(1000)),
            config: config.clone(),
        })
    }

    /// Escalate an incident
    pub async fn escalate(
        &self,
        level: EscalationLevel,
        request: &Request,
        risk_score: &RiskScore,
    ) -> Result<(), SentinelError> {
        // Reset daily counter if needed
        self.maybe_reset_counter();

        // Increment counter
        self.today_count.fetch_add(1, Ordering::Relaxed);

        // Create event
        let event = EscalationEvent {
            level,
            client_ip: request.client_ip.to_string(),
            path: request.path.clone(),
            risk_score: risk_score.total_score(),
            flags: risk_score.flags.iter().map(|f| format!("{:?}", f)).collect(),
            timestamp: Instant::now(),
            timestamp_str: chrono::Utc::now().to_rfc3339(),
        };

        // Log the escalation
        match level {
            EscalationLevel::Critical => {
                tracing::error!(
                    level = "CRITICAL",
                    ip = %event.client_ip,
                    path = %event.path,
                    score = event.risk_score,
                    flags = ?event.flags,
                    "SECURITY ESCALATION"
                );
            }
            EscalationLevel::High => {
                tracing::warn!(
                    level = "HIGH",
                    ip = %event.client_ip,
                    path = %event.path,
                    score = event.risk_score,
                    flags = ?event.flags,
                    "Security escalation"
                );
            }
            EscalationLevel::Medium => {
                tracing::info!(
                    level = "MEDIUM",
                    ip = %event.client_ip,
                    path = %event.path,
                    score = event.risk_score,
                    "Security alert"
                );
            }
            EscalationLevel::Low => {
                tracing::debug!(
                    level = "LOW",
                    ip = %event.client_ip,
                    path = %event.path,
                    score = event.risk_score,
                    "Security notice"
                );
            }
        }

        // Store in recent
        {
            let mut recent = self.recent.write().unwrap();
            recent.push_back(event);
            if recent.len() > 1000 {
                recent.pop_front();
            }
        }

        // TODO: Send to external alerting systems
        // - PagerDuty for Critical
        // - Slack for High
        // - Dashboard only for Medium/Low

        Ok(())
    }

    /// Get today's escalation count
    pub fn today_count(&self) -> usize {
        self.maybe_reset_counter();
        self.today_count.load(Ordering::Relaxed)
    }

    /// Get recent escalations
    pub fn get_recent(&self, limit: usize) -> Vec<EscalationEvent> {
        let recent = self.recent.read().unwrap();
        recent.iter().rev().take(limit).cloned().collect()
    }

    /// Get escalations by level
    pub fn get_by_level(&self, level: EscalationLevel, limit: usize) -> Vec<EscalationEvent> {
        let recent = self.recent.read().unwrap();
        recent
            .iter()
            .rev()
            .filter(|e| e.level == level)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Maybe reset daily counter
    fn maybe_reset_counter(&self) {
        let mut last_reset = self.last_reset.write().unwrap();
        let now = Instant::now();

        // Reset every 24 hours
        if now.duration_since(*last_reset) > Duration::from_secs(86400) {
            self.today_count.store(0, Ordering::Relaxed);
            *last_reset = now;
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> EscalationStats {
        let recent = self.recent.read().unwrap();

        let critical = recent.iter().filter(|e| e.level == EscalationLevel::Critical).count();
        let high = recent.iter().filter(|e| e.level == EscalationLevel::High).count();
        let medium = recent.iter().filter(|e| e.level == EscalationLevel::Medium).count();
        let low = recent.iter().filter(|e| e.level == EscalationLevel::Low).count();

        EscalationStats {
            total: recent.len(),
            critical,
            high,
            medium,
            low,
        }
    }
}

/// Escalation statistics
#[derive(Debug, Clone)]
pub struct EscalationStats {
    /// Total escalations
    pub total: usize,
    /// Critical count
    pub critical: usize,
    /// High count
    pub high: usize,
    /// Medium count
    pub medium: usize,
    /// Low count
    pub low: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_escalate() {
        let config = ResponseConfig::default();
        let manager = EscalationManager::new(&config).unwrap();

        let request = Request {
            path: "/api/test".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };

        let risk_score = RiskScore::default();

        manager.escalate(EscalationLevel::High, &request, &risk_score).await.unwrap();

        assert_eq!(manager.today_count(), 1);
    }

    #[tokio::test]
    async fn test_recent_escalations() {
        let config = ResponseConfig::default();
        let manager = EscalationManager::new(&config).unwrap();

        for i in 0..5 {
            let request = Request {
                path: format!("/api/test/{}", i),
                client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, i as u8)),
                ..Default::default()
            };

            let risk_score = RiskScore::default();
            manager.escalate(EscalationLevel::Medium, &request, &risk_score).await.unwrap();
        }

        let recent = manager.get_recent(10);
        assert_eq!(recent.len(), 5);
    }
}
