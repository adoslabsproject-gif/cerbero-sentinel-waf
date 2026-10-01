//! Action Engine
//!
//! Determines and records enforcement actions.

use sentinel_core::{Action, Request, ResponseConfig, LayerRiskScore as RiskScore, SentinelError};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Most recent actions kept per IP. Past this the oldest half is dropped.
const MAX_HISTORY_PER_IP: usize = 100;

/// Result of action determination
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// The action to take
    pub action: Action,
    /// Confidence in this action
    pub confidence: f64,
    /// Reason for action
    pub reason: String,
}

/// Action statistics
#[derive(Debug, Default)]
struct ActionStats {
    allows: AtomicU64,
    blocks: AtomicU64,
    challenges: AtomicU64,
    rate_limits: AtomicU64,
}

/// Action history entry
#[derive(Debug, Clone)]
pub struct ActionEntry {
    pub action: Action,
    pub risk_score: f64,
    pub timestamp: Instant,
}

/// Action engine for determining and tracking enforcement
pub struct ActionEngine {
    /// Action statistics
    stats: ActionStats,
    /// Recent actions for learning
    recent_actions: Arc<DashMap<String, Vec<ActionEntry>>>,
    /// Configuration
    #[allow(dead_code)]
    config: ResponseConfig,
}

impl ActionEngine {
    /// Create new action engine
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            stats: ActionStats::default(),
            recent_actions: Arc::new(DashMap::new()),
            config: config.clone(),
        })
    }

    /// Record an action for learning
    pub async fn record_action(&self, request: &Request, action: &Action, risk_score: &RiskScore) {
        // Update stats
        match action {
            Action::Allow => self.stats.allows.fetch_add(1, Ordering::Relaxed),
            Action::Block { .. } => self.stats.blocks.fetch_add(1, Ordering::Relaxed),
            Action::Challenge(_) => self.stats.challenges.fetch_add(1, Ordering::Relaxed),
            Action::RateLimit { .. } => self.stats.rate_limits.fetch_add(1, Ordering::Relaxed),
        };

        // Record for IP
        let key = request.client_ip.to_string();
        let entry = ActionEntry {
            action: action.clone(),
            risk_score: risk_score.total_score(),
            timestamp: Instant::now(),
        };

        // Trim ONLY the entry we just touched. The previous version walked the
        // whole map on every single request — one lock per attacker IP ever seen —
        // to prune a single vector: O(unique IPs) of work on the hot path.
        let mut entries = self.recent_actions.entry(key).or_insert_with(Vec::new);
        entries.push(entry);
        if entries.len() > MAX_HISTORY_PER_IP {
            entries.drain(0..MAX_HISTORY_PER_IP / 2);
        }
    }

    /// Forget the action history of IPs that have been quiet for `max_age`.
    ///
    /// `recent_actions` holds one key per IP and nothing ever removed them, so the
    /// map grew for the whole life of the process. Returns how many IPs were
    /// forgotten.
    pub fn cleanup(&self, max_age: std::time::Duration) -> usize {
        let before = self.recent_actions.len();
        let now = Instant::now();
        self.recent_actions.retain(|_, entries| match entries.last() {
            Some(last) => now.duration_since(last.timestamp) < max_age,
            // No entries left at all: nothing worth a key.
            None => false,
        });
        before - self.recent_actions.len()
    }

    /// How many IPs the action history currently holds.
    pub fn tracked_ip_count(&self) -> usize {
        self.recent_actions.len()
    }

    /// Get action history for an IP
    pub fn get_history(&self, ip: &str) -> Vec<ActionEntry> {
        self.recent_actions
            .get(ip)
            .map(|e| e.value().clone())
            .unwrap_or_default()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.allows.load(Ordering::Relaxed),
            self.stats.blocks.load(Ordering::Relaxed),
            self.stats.challenges.load(Ordering::Relaxed),
            self.stats.rate_limits.load(Ordering::Relaxed),
        )
    }

    /// Check if IP has been blocked recently
    pub fn was_recently_blocked(&self, ip: &str) -> bool {
        self.recent_actions
            .get(ip)
            .map(|entries| {
                entries.iter().rev().take(5).any(|e| matches!(e.action, Action::Block { .. }))
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_record_action() {
        let config = ResponseConfig::default();
        let engine = ActionEngine::new(&config).unwrap();

        let request = Request {
            client_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            ..Default::default()
        };

        let risk_score = RiskScore::default();

        engine.record_action(&request, &Action::Allow, &risk_score).await;

        let (allows, _, _, _) = engine.get_stats();
        assert_eq!(allows, 1);
    }
}
