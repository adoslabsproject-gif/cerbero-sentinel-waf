//! Ban Management
//!
//! Manages IP and agent bans with automatic expiration.

use sentinel_core::{AgentId, ResponseConfig, SentinelError};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Reason for ban
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Critical risk score
    CriticalRisk,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Failed too many challenges
    ChallengeFailed,
    /// Manual ban by admin
    Manual,
    /// Coordinated attack detected
    CoordinatedAttack,
    /// Prompt injection attempt
    PromptInjection,
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanReason::CriticalRisk => write!(f, "Critical security risk"),
            BanReason::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            BanReason::ChallengeFailed => write!(f, "Failed security challenge"),
            BanReason::Manual => write!(f, "Manual ban"),
            BanReason::CoordinatedAttack => write!(f, "Coordinated attack detected"),
            BanReason::PromptInjection => write!(f, "Prompt injection attempt"),
        }
    }
}

/// Ban entry
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// Reason for ban
    pub reason: BanReason,
    /// When banned
    pub banned_at: Instant,
    /// When ban expires
    pub expires_at: Instant,
    /// Number of times banned
    pub ban_count: u32,
}

impl BanEntry {
    fn new(reason: BanReason, duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            reason,
            banned_at: now,
            expires_at: now + duration,
            ban_count: 1,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    fn time_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    fn extend(&mut self, reason: BanReason, duration: Duration) {
        self.reason = reason;
        self.expires_at = Instant::now() + duration;
        self.ban_count += 1;
    }
}

/// Ban manager
pub struct BanManager {
    /// IP bans
    ip_bans: Arc<DashMap<IpAddr, BanEntry>>,
    /// Agent bans
    agent_bans: Arc<DashMap<AgentId, BanEntry>>,
    /// Configuration
    #[allow(dead_code)]
    config: ResponseConfig,
}

impl BanManager {
    /// Create new ban manager
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            ip_bans: Arc::new(DashMap::new()),
            agent_bans: Arc::new(DashMap::new()),
            config: config.clone(),
        })
    }

    /// Check if IP is banned
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.ip_bans.get(ip) {
            if entry.is_expired() {
                drop(entry);
                self.ip_bans.remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Check if agent is banned
    pub async fn is_agent_banned(&self, agent_id: &AgentId) -> bool {
        if let Some(entry) = self.agent_bans.get(agent_id) {
            if entry.is_expired() {
                drop(entry);
                self.agent_bans.remove(agent_id);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Ban an IP
    pub async fn ban_ip(&self, ip: IpAddr, reason: BanReason, duration: Duration) {
        self.ip_bans
            .entry(ip)
            .and_modify(|e| e.extend(reason, duration))
            .or_insert_with(|| BanEntry::new(reason, duration));

        tracing::warn!(
            ip = %ip,
            reason = %reason,
            duration_secs = duration.as_secs(),
            "IP banned"
        );
    }

    /// Ban an agent
    pub async fn ban_agent(&self, agent_id: AgentId, reason: BanReason, duration: Duration) {
        self.agent_bans
            .entry(agent_id.clone())
            .and_modify(|e| e.extend(reason, duration))
            .or_insert_with(|| BanEntry::new(reason, duration));

        tracing::warn!(
            agent_id = %agent_id,
            reason = %reason,
            duration_secs = duration.as_secs(),
            "Agent banned"
        );
    }

    /// Unban an IP
    pub async fn unban_ip(&self, ip: &IpAddr) {
        self.ip_bans.remove(ip);
        tracing::info!(ip = %ip, "IP unbanned");
    }

    /// Unban an agent
    pub async fn unban_agent(&self, agent_id: &AgentId) {
        self.agent_bans.remove(agent_id);
        tracing::info!(agent_id = %agent_id, "Agent unbanned");
    }

    /// Get time until IP unban
    pub async fn time_until_unban(&self, ip: &IpAddr) -> Duration {
        self.ip_bans
            .get(ip)
            .map(|e| e.time_remaining())
            .unwrap_or(Duration::ZERO)
    }

    /// Get time until agent unban
    pub async fn time_until_agent_unban(&self, agent_id: &AgentId) -> Duration {
        self.agent_bans
            .get(agent_id)
            .map(|e| e.time_remaining())
            .unwrap_or(Duration::ZERO)
    }

    /// Get ban info for IP
    pub async fn get_ban_info(&self, ip: &IpAddr) -> Option<BanEntry> {
        self.ip_bans.get(ip).map(|e| e.clone())
    }

    /// Get ban info for agent
    pub async fn get_agent_ban_info(&self, agent_id: &AgentId) -> Option<BanEntry> {
        self.agent_bans.get(agent_id).map(|e| e.clone())
    }

    /// Get active ban count
    pub fn active_ban_count(&self) -> usize {
        self.ip_bans.len() + self.agent_bans.len()
    }

    /// Get all banned IPs
    pub fn get_banned_ips(&self) -> Vec<(IpAddr, BanEntry)> {
        self.ip_bans
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }

    /// Cleanup expired bans
    pub async fn cleanup(&self) {
        self.ip_bans.retain(|_, e| !e.is_expired());
        self.agent_bans.retain(|_, e| !e.is_expired());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ban_ip() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(!manager.is_banned(&ip).await);

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;

        assert!(manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_unban_ip() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;
        assert!(manager.is_banned(&ip).await);

        manager.unban_ip(&ip).await;
        assert!(!manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_ban_expiration() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Ban for very short duration
        manager.ban_ip(ip, BanReason::Manual, Duration::from_millis(1)).await;

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should be unbanned now
        assert!(!manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_ban_count() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;
        manager.ban_ip(ip, BanReason::RateLimitExceeded, Duration::from_secs(60)).await;

        let info = manager.get_ban_info(&ip).await.unwrap();
        assert_eq!(info.ban_count, 2);
    }
}
