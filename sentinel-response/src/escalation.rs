//! Escalation Management
//!
//! Handles alert escalation to security teams:
//! - Logging at appropriate severity levels
//! - Webhook to Node.js API for Telegram alerts
//! - Rate limiting (10 alerts/min global, 1 per IP per 5 min)
//! - Recent escalation history

use sentinel_core::{Request, ResponseConfig, LayerRiskScore as RiskScore, SentinelError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Escalation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EscalationLevel {
    /// Low priority - logged only
    Low,
    /// Medium priority - alert to dashboard
    Medium,
    /// High priority - webhook alert
    High,
    /// Critical - immediate webhook alert
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

/// Webhook payload sent to Node.js API
#[derive(Debug, Clone, serde::Serialize)]
pub struct EscalationPayload {
    /// Escalation level
    pub level: String,
    /// Client IP
    pub ip: String,
    /// Request path
    pub path: String,
    /// Risk score (0.0-1.0)
    pub risk_score: f64,
    /// Risk flag names
    pub flags: Vec<String>,
    /// Event count in the last hour
    pub event_count: u32,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

/// Rate limit tracking for webhook alerts
struct WebhookRateLimiter {
    /// Global alert timestamps (last minute)
    global_alerts: RwLock<VecDeque<Instant>>,
    /// Per-IP last alert time
    per_ip_last_alert: RwLock<HashMap<String, Instant>>,
}

impl WebhookRateLimiter {
    fn new() -> Self {
        Self {
            global_alerts: RwLock::new(VecDeque::with_capacity(20)),
            per_ip_last_alert: RwLock::new(HashMap::new()),
        }
    }

    /// Check if we can send a webhook alert (rate limiting)
    fn can_send(&self, ip: &str) -> bool {
        let now = Instant::now();

        // Global: max 10 alerts per minute.
        // HIGH (2026-05-29): poisoned-safe lock recovery. `.unwrap()` su
        // RwLock propaga il panic a tutti i lock subsequent → cascading
        // failure. `.unwrap_or_else(|p| p.into_inner())` recupera lo state
        // (anche se potenzialmente inconsistente — accettabile su counter
        // di rate-limit dove un alert in piu\` o in meno e\` benigno).
        {
            let mut global = self.global_alerts.write();
            let cutoff = now - Duration::from_secs(60);
            while global.front().map(|&t| t < cutoff).unwrap_or(false) {
                global.pop_front();
            }
            if global.len() >= 10 {
                return false;
            }
        }

        // Per-IP: max 1 alert per 5 minutes
        {
            let per_ip = self.per_ip_last_alert.read();
            if let Some(last) = per_ip.get(ip) {
                if now.duration_since(*last) < Duration::from_secs(300) {
                    return false;
                }
            }
        }

        true
    }

    /// Record that an alert was sent
    fn record_send(&self, ip: &str) {
        let now = Instant::now();
        self.global_alerts.write().push_back(now);
        self.per_ip_last_alert.write().insert(ip.to_string(), now);
    }
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
    /// Webhook URL (from env SENTINEL_ESCALATION_WEBHOOK_URL)
    webhook_url: Option<String>,
    /// Webhook secret (from env SENTINEL_ESCALATION_WEBHOOK_SECRET)
    webhook_secret: Option<String>,
    /// Rate limiter for webhook alerts
    rate_limiter: WebhookRateLimiter,
}

impl EscalationManager {
    /// Create new escalation manager
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        let webhook_url = std::env::var("SENTINEL_ESCALATION_WEBHOOK_URL").ok();
        let webhook_secret = std::env::var("SENTINEL_ESCALATION_WEBHOOK_SECRET").ok();

        if webhook_url.is_some() {
            tracing::info!("Escalation webhook configured");
        } else {
            tracing::info!("No escalation webhook configured — logging only");
        }

        Ok(Self {
            today_count: AtomicUsize::new(0),
            last_reset: RwLock::new(Instant::now()),
            recent: RwLock::new(VecDeque::with_capacity(1000)),
            config: config.clone(),
            webhook_url,
            webhook_secret,
            rate_limiter: WebhookRateLimiter::new(),
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

        // Store in recent (poisoned-safe — HIGH 2026-05-29)
        {
            let mut recent = self.recent.write();
            recent.push_back(event.clone());
            if recent.len() > 1000 {
                recent.pop_front();
            }
        }

        // Send webhook for Critical and High (Medium = too noisy)
        if matches!(level, EscalationLevel::Critical | EscalationLevel::High) {
            self.send_webhook(&event).await;
        }

        Ok(())
    }

    /// Send webhook notification to Node.js API (fire-and-forget)
    async fn send_webhook(&self, event: &EscalationEvent) {
        let url = match &self.webhook_url {
            Some(url) => url.clone(),
            None => return, // No webhook configured
        };

        // Rate limiting
        if !self.rate_limiter.can_send(&event.client_ip) {
            tracing::debug!(
                ip = %event.client_ip,
                "Escalation webhook rate limited"
            );
            return;
        }

        self.rate_limiter.record_send(&event.client_ip);

        let payload = EscalationPayload {
            level: match event.level {
                EscalationLevel::Critical => "critical".to_string(),
                EscalationLevel::High => "high".to_string(),
                EscalationLevel::Medium => "medium".to_string(),
                EscalationLevel::Low => "low".to_string(),
            },
            ip: event.client_ip.clone(),
            path: event.path.clone(),
            risk_score: event.risk_score,
            flags: event.flags.clone(),
            event_count: self.today_count.load(Ordering::Relaxed) as u32,
            timestamp: event.timestamp_str.clone(),
        };

        let secret = self.webhook_secret.clone();

        // Fire-and-forget with 2s timeout
        #[cfg(feature = "webhook")]
        {
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build();

                let client = match client {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to create webhook client");
                        return;
                    }
                };

                let mut req = client.post(&url).json(&payload);
                if let Some(secret) = secret {
                    req = req.header("x-internal-secret", secret);
                }

                match req.send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            tracing::warn!(
                                status = %resp.status(),
                                "Escalation webhook returned non-success"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Escalation webhook failed (fire-and-forget)"
                        );
                    }
                }
            });
        }

        #[cfg(not(feature = "webhook"))]
        {
            let _ = (payload, secret);
            tracing::debug!("Webhook feature not enabled — skipping HTTP call");
        }
    }

    /// Get today's escalation count
    pub fn today_count(&self) -> usize {
        self.maybe_reset_counter();
        self.today_count.load(Ordering::Relaxed)
    }

    /// Get recent escalations
    pub fn get_recent(&self, limit: usize) -> Vec<EscalationEvent> {
        let recent = self.recent.read();
        recent.iter().rev().take(limit).cloned().collect()
    }

    /// Get escalations by level
    pub fn get_by_level(&self, level: EscalationLevel, limit: usize) -> Vec<EscalationEvent> {
        let recent = self.recent.read();
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
        let mut last_reset = self.last_reset.write();
        let now = Instant::now();

        // Reset every 24 hours
        if now.duration_since(*last_reset) > Duration::from_secs(86400) {
            self.today_count.store(0, Ordering::Relaxed);
            *last_reset = now;
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> EscalationStats {
        let recent = self.recent.read();

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

    #[test]
    fn test_webhook_rate_limiter() {
        let limiter = WebhookRateLimiter::new();

        // First alert should be allowed
        assert!(limiter.can_send("1.2.3.4"));
        limiter.record_send("1.2.3.4");

        // Same IP within 5 min should be blocked
        assert!(!limiter.can_send("1.2.3.4"));

        // Different IP should be allowed
        assert!(limiter.can_send("5.6.7.8"));
    }

    // HIGH (2026-05-29): regression test poisoned-safe lock recovery.
    // Forziamo poison del RwLock (panic dentro write()) e verifichiamo
    // che le successive read() / write() NON panic ma recuperino state.
    #[test]
    fn test_poisoned_rwlock_recovery_recent() {
        let config = ResponseConfig::default();
        let manager = std::sync::Arc::new(EscalationManager::new(&config).unwrap());

        // Poison: spawn thread che panic-a tenendo il write lock.
        let m2 = manager.clone();
        let h = std::thread::spawn(move || {
            let _w = m2.recent.write();
            panic!("intentional poison");
        });
        let _ = h.join(); // collect panic

        // Read post-poison NON deve panic — `.unwrap_or_else(|p| p.into_inner())`
        let recent = manager.get_recent(10);
        assert_eq!(recent.len(), 0);

        // Stats anche non-panic
        let stats = manager.get_stats();
        assert_eq!(stats.critical, 0);
    }

    #[test]
    fn test_poisoned_rwlock_recovery_webhook_limiter() {
        let limiter = std::sync::Arc::new(WebhookRateLimiter::new());

        // Poison global_alerts via panic in write()
        let l2 = limiter.clone();
        let h = std::thread::spawn(move || {
            let _w = l2.global_alerts.write();
            panic!("intentional poison global");
        });
        let _ = h.join();

        // can_send NON deve panic
        assert!(limiter.can_send("9.9.9.9"));
        limiter.record_send("9.9.9.9");
        assert!(!limiter.can_send("9.9.9.9")); // second within window
    }
}
