//! SENTINEL Middleware
//!
//! Middleware adapter for integrating SENTINEL with web frameworks.

use sentinel_core::{Action, AgentId, Request, SentinelError};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use crate::Sentinel;

/// Convert HTTP request to SENTINEL request
pub fn to_sentinel_request(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    client_ip: IpAddr,
) -> Request {
    let headers_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let body = body.and_then(|b| {
        // Try to parse as JSON first
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(b) {
            Some(sentinel_core::RequestBody::Json(json))
        } else if let Ok(text) = std::str::from_utf8(b) {
            Some(sentinel_core::RequestBody::Text(text.to_string()))
        } else {
            Some(sentinel_core::RequestBody::Binary(b.to_vec()))
        }
    });

    Request {
        method: method.to_string(),
        path: path.to_string(),
        query_string: query.map(|s| s.to_string()),
        headers: headers_map,
        body,
        client_ip,
        ..Default::default()
    }
}

/// Extract agent ID from request (JWT or API key)
pub fn extract_agent_id(headers: &HashMap<String, String>) -> Option<AgentId> {
    // Try Authorization header
    if let Some(auth) = headers.get("authorization") {
        if auth.starts_with("Bearer ") {
            // In production, this would verify and decode the JWT
            // For now, we'll use a placeholder
            return Some(AgentId::from_token(&auth[7..]));
        }
    }

    // Try X-Agent-ID header
    if let Some(agent_id) = headers.get("x-agent-id") {
        return Some(AgentId::new_from_string(agent_id));
    }

    None
}

/// SENTINEL middleware handler
pub struct SentinelMiddleware {
    sentinel: Arc<Sentinel>,
}

impl SentinelMiddleware {
    /// Create new middleware
    pub fn new(sentinel: Arc<Sentinel>) -> Self {
        Self { sentinel }
    }

    /// Process a request
    pub async fn process(
        &self,
        request: &Request,
    ) -> Result<MiddlewareResult, SentinelError> {
        let agent_id = extract_agent_id(&request.headers);

        let action = self.sentinel
            .process(request, agent_id.as_ref())
            .await?;

        Ok(MiddlewareResult::from_action(action))
    }
}

/// Result from middleware processing
#[derive(Debug)]
pub enum MiddlewareResult {
    /// Allow the request to proceed
    Allow,
    /// Block the request
    Block {
        status_code: u16,
        body: String,
        retry_after: Option<u64>,
    },
    /// Request requires challenge
    Challenge {
        status_code: u16,
        body: String,
        challenge_id: String,
    },
    /// Rate limit applied
    RateLimit {
        remaining: u32,
        reset_at: u64,
    },
}

impl MiddlewareResult {
    fn from_action(action: Action) -> Self {
        match action {
            Action::Allow => MiddlewareResult::Allow,

            Action::Block { reason, retry_after } => MiddlewareResult::Block {
                status_code: 403,
                body: serde_json::json!({
                    "error": "Forbidden",
                    "message": reason,
                    "retry_after": retry_after.map(|d| d.as_secs()),
                }).to_string(),
                retry_after: retry_after.map(|d| d.as_secs()),
            },

            Action::Challenge(challenge) => MiddlewareResult::Challenge {
                status_code: 429,
                body: serde_json::json!({
                    "error": "Challenge Required",
                    "challenge": {
                        "id": challenge.id,
                        "type": format!("{:?}", challenge.challenge_type),
                        "data": challenge.data,
                        "expires_in": challenge.expires_in.as_secs(),
                    }
                }).to_string(),
                challenge_id: challenge.id,
            },

            Action::RateLimit { requests_per_minute } => MiddlewareResult::RateLimit {
                remaining: requests_per_minute,
                reset_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 60,
            },
        }
    }

    /// Get HTTP status code
    pub fn status_code(&self) -> u16 {
        match self {
            MiddlewareResult::Allow => 200,
            MiddlewareResult::Block { status_code, .. } => *status_code,
            MiddlewareResult::Challenge { status_code, .. } => *status_code,
            MiddlewareResult::RateLimit { .. } => 200,
        }
    }

    /// Check if request should proceed
    pub fn should_proceed(&self) -> bool {
        matches!(self, MiddlewareResult::Allow | MiddlewareResult::RateLimit { .. })
    }

    /// Get response headers
    pub fn headers(&self) -> Vec<(String, String)> {
        match self {
            MiddlewareResult::Allow => vec![],

            MiddlewareResult::Block { retry_after, .. } => {
                let mut headers = vec![];
                if let Some(retry) = retry_after {
                    headers.push(("Retry-After".to_string(), retry.to_string()));
                }
                headers
            }

            MiddlewareResult::Challenge { challenge_id, .. } => {
                vec![("X-Challenge-ID".to_string(), challenge_id.clone())]
            }

            MiddlewareResult::RateLimit { remaining, reset_at } => {
                vec![
                    ("X-RateLimit-Remaining".to_string(), remaining.to_string()),
                    ("X-RateLimit-Reset".to_string(), reset_at.to_string()),
                ]
            }
        }
    }

    /// Get response body (if any)
    pub fn body(&self) -> Option<&str> {
        match self {
            MiddlewareResult::Allow => None,
            MiddlewareResult::Block { body, .. } => Some(body),
            MiddlewareResult::Challenge { body, .. } => Some(body),
            MiddlewareResult::RateLimit { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_to_sentinel_request() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "TestAgent/1.0".to_string()),
        ];

        let request = to_sentinel_request(
            "POST",
            "/api/posts",
            Some("page=1"),
            &headers,
            Some(b"{\"title\": \"Test\"}"),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/posts");
        assert_eq!(request.query_string, Some("page=1".to_string()));
        assert!(request.body.is_some());
    }

    #[test]
    fn test_extract_agent_id() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer test_token".to_string());

        let agent_id = extract_agent_id(&headers);
        assert!(agent_id.is_some());
    }
}
