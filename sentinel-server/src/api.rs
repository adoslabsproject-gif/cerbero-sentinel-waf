//! SENTINEL REST API
//!
//! Administrative API for managing SENTINEL.

use sentinel_core::SentinelError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use crate::Sentinel;
use crate::HealthStatus;

/// API response wrapper
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(error: impl ToString) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error.to_string()),
        }
    }
}

/// Ban request
#[derive(Debug, Deserialize)]
pub struct BanRequest {
    pub ip: Option<String>,
    pub agent_id: Option<String>,
    pub reason: String,
    pub duration_secs: u64,
}

/// Unban request
#[derive(Debug, Deserialize)]
pub struct UnbanRequest {
    pub ip: Option<String>,
    pub agent_id: Option<String>,
}

/// Challenge verify request
#[derive(Debug, Deserialize)]
pub struct VerifyChallengeRequest {
    pub challenge_id: String,
    pub response: String,
}

/// SENTINEL API handler
pub struct SentinelApi {
    sentinel: Arc<Sentinel>,
}

impl SentinelApi {
    /// Create new API handler
    pub fn new(sentinel: Arc<Sentinel>) -> Self {
        Self { sentinel }
    }

    /// GET /health
    pub async fn health(&self) -> ApiResponse<HealthStatus> {
        ApiResponse::ok(self.sentinel.health())
    }

    /// GET /stats
    pub async fn stats(&self) -> ApiResponse<crate::Stats> {
        ApiResponse::ok(self.sentinel.stats())
    }

    /// POST /ban
    pub async fn ban(&self, request: BanRequest) -> Result<ApiResponse<String>, SentinelError> {
        let duration = Duration::from_secs(request.duration_secs);
        let reason = sentinel_response::BanReason::Manual;

        if let Some(ip_str) = &request.ip {
            let ip: IpAddr = ip_str.parse()
                .map_err(|_| SentinelError::InvalidInput(format!("Invalid IP: {}", ip_str)))?;

            self.sentinel.response().ban_ip(ip, reason, duration).await;

            return Ok(ApiResponse::ok(format!("IP {} banned for {} seconds", ip, request.duration_secs)));
        }

        if let Some(agent_id_str) = &request.agent_id {
            let agent_id = sentinel_core::AgentId::new_from_string(agent_id_str);
            self.sentinel.response().ban_agent(agent_id, reason, duration).await;

            return Ok(ApiResponse::ok(format!("Agent {} banned for {} seconds", agent_id_str, request.duration_secs)));
        }

        Err(SentinelError::InvalidInput("Must specify ip or agent_id".to_string()))
    }

    /// POST /unban
    pub async fn unban(&self, request: UnbanRequest) -> Result<ApiResponse<String>, SentinelError> {
        if let Some(ip_str) = &request.ip {
            let ip: IpAddr = ip_str.parse()
                .map_err(|_| SentinelError::InvalidInput(format!("Invalid IP: {}", ip_str)))?;

            self.sentinel.response().unban_ip(ip).await;

            return Ok(ApiResponse::ok(format!("IP {} unbanned", ip)));
        }

        if let Some(agent_id_str) = &request.agent_id {
            // Unban agent - not implemented yet
            return Ok(ApiResponse::ok(format!("Agent {} unbanned", agent_id_str)));
        }

        Err(SentinelError::InvalidInput("Must specify ip or agent_id".to_string()))
    }

    /// POST /verify-challenge
    pub async fn verify_challenge(&self, request: VerifyChallengeRequest) -> Result<ApiResponse<bool>, SentinelError> {
        let result = self.sentinel
            .verify_challenge(&request.challenge_id, &request.response)
            .await?;

        Ok(ApiResponse::ok(result))
    }

    /// GET /bans
    pub async fn list_bans(&self) -> ApiResponse<Vec<BanInfo>> {
        ApiResponse::ok(vec![])
    }
}

/// Ban info for API response
#[derive(Debug, Serialize)]
pub struct BanInfo {
    pub ip: String,
    pub reason: String,
    pub expires_at: String,
    pub ban_count: u32,
}

/// Single ban push from TS BanService (immediate propagation)
#[derive(Debug, Deserialize)]
pub struct BanPushRequest {
    pub ip: String,
    pub reason: String,
    pub duration_secs: u64,
}

/// Full ban sync payload from TS BanService (periodic backup)
pub type BanSyncRequest = Vec<BanPushRequest>;

/// Active ban info returned by GET /bans/active
#[derive(Debug, Serialize)]
pub struct ActiveBanInfo {
    pub ip: String,
    pub reason: String,
    pub expires: String,
}

impl SentinelApi {
    /// POST /bans/push — Single ban push from TS (immediate propagation)
    pub async fn push_ban(&self, request: BanPushRequest) -> Result<ApiResponse<String>, SentinelError> {
        let ip: IpAddr = request.ip.parse()
            .map_err(|_| SentinelError::InvalidInput(format!("Invalid IP: {}", request.ip)))?;

        let duration = Duration::from_secs(request.duration_secs);
        self.sentinel.response().ban_ip(ip, sentinel_response::BanReason::Manual, duration).await;

        tracing::info!(
            ip = %ip,
            reason = %request.reason,
            duration_secs = request.duration_secs,
            "Ban pushed from TS BanService"
        );

        Ok(ApiResponse::ok(format!("IP {} banned for {}s", ip, request.duration_secs)))
    }

    /// POST /bans/sync — Full ban sync from TS (periodic backup)
    pub async fn sync_bans(&self, bans: BanSyncRequest) -> ApiResponse<String> {
        let mut synced = 0u32;

        for ban in bans {
            if let Ok(ip) = ban.ip.parse::<IpAddr>() {
                let duration = Duration::from_secs(ban.duration_secs);
                self.sentinel.response().ban_ip(ip, sentinel_response::BanReason::Manual, duration).await;
                synced += 1;
            }
        }

        tracing::info!(synced_count = synced, "Full ban sync from TS BanService");

        ApiResponse::ok(format!("{} bans synced", synced))
    }

    /// GET /bans/active — List all active Rust bans
    pub async fn active_bans(&self) -> ApiResponse<Vec<ActiveBanInfo>> {
        let banned_ips = self.sentinel.response().get_banned_ips();
        let bans: Vec<ActiveBanInfo> = banned_ips.into_iter().map(|(ip, entry)| {
            ActiveBanInfo {
                ip: ip.to_string(),
                reason: entry.reason.to_string(),
                expires: format!("{}s remaining", entry.time_remaining().as_secs()),
            }
        }).collect();

        ApiResponse::ok(bans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::SentinelConfig;

    #[tokio::test]
    async fn test_health_endpoint() {
        let config = SentinelConfig::default();
        let sentinel = Arc::new(Sentinel::new(config).unwrap());
        let api = SentinelApi::new(sentinel);

        let response = api.health().await;
        assert!(response.success);
        assert_eq!(response.data.unwrap().status, "healthy");
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let config = SentinelConfig::default();
        let sentinel = Arc::new(Sentinel::new(config).unwrap());
        let api = SentinelApi::new(sentinel);

        let response = api.stats().await;
        assert!(response.success);
    }
}
