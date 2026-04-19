//! Request types for SENTINEL

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

/// Incoming request to be analyzed by SENTINEL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Unique request ID for tracing
    #[serde(default = "default_uuid")]
    pub id: Uuid,

    /// Timestamp of the request
    #[serde(default = "default_timestamp")]
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Client IP address (legacy field)
    #[serde(default = "default_ip")]
    pub ip: IpAddr,

    /// Client IP address (new field for compatibility)
    #[serde(default = "default_ip")]
    pub client_ip: IpAddr,

    /// HTTP method (legacy enum)
    #[serde(default)]
    pub http_method: HttpMethod,

    /// HTTP method (string for compatibility)
    #[serde(default)]
    pub method: String,

    /// Request path
    #[serde(default)]
    pub path: String,

    /// Query parameters
    #[serde(default)]
    pub query: HashMap<String, String>,

    /// Query string (raw)
    pub query_string: Option<String>,

    /// Request headers (sanitized - no auth tokens)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request body (if applicable)
    pub body: Option<RequestBody>,

    /// Agent ID (from JWT, if authenticated)
    pub agent_id: Option<String>,

    /// Agent name (from JWT, if authenticated)
    pub agent_name: Option<String>,

    /// Additional context
    #[serde(default)]
    pub context: RequestContext,
}

fn default_uuid() -> Uuid {
    Uuid::now_v7()
}

fn default_timestamp() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn default_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

impl Default for Request {
    fn default() -> Self {
        Self {
            id: Uuid::now_v7(),
            timestamp: chrono::Utc::now(),
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            http_method: HttpMethod::Get,
            method: "GET".to_string(),
            path: "/".to_string(),
            query: HashMap::new(),
            query_string: None,
            headers: HashMap::new(),
            body: None,
            agent_id: None,
            agent_name: None,
            context: RequestContext::default(),
        }
    }
}

impl Request {
    /// Create a new request with auto-generated ID
    pub fn new(ip: IpAddr, method: HttpMethod, path: String) -> Self {
        Self {
            id: Uuid::now_v7(),
            timestamp: chrono::Utc::now(),
            ip,
            client_ip: ip,
            http_method: method,
            method: method.to_string(),
            path,
            query: HashMap::new(),
            query_string: None,
            headers: HashMap::new(),
            body: None,
            agent_id: None,
            agent_name: None,
            context: RequestContext::default(),
        }
    }

    /// Check if this is a write operation
    pub fn is_write(&self) -> bool {
        matches!(
            self.http_method,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete
        )
    }

    /// Get the user agent header
    pub fn user_agent(&self) -> Option<&str> {
        self.headers.get("user-agent").map(|s| s.as_str())
    }

    /// Get content length
    pub fn content_length(&self) -> usize {
        match &self.body {
            Some(RequestBody::Text(t)) => t.len(),
            Some(RequestBody::Json(j)) => j.to_string().len(),
            Some(RequestBody::Binary(b)) => b.len(),
            None => 0,
        }
    }

    /// Extract text content from body (for ML analysis)
    pub fn text_content(&self) -> Option<String> {
        match &self.body {
            Some(RequestBody::Text(t)) => Some(t.clone()),
            Some(RequestBody::Json(j)) => {
                // Try common content fields
                j.get("content")
                    .or_else(|| j.get("text"))
                    .or_else(|| j.get("body"))
                    .or_else(|| j.get("title"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            }
            Some(RequestBody::Binary(b)) => String::from_utf8(b.clone()).ok(),
            None => None,
        }
    }
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

/// Request body information (structured)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBodyInfo {
    /// Content type
    pub content_type: String,

    /// Body size in bytes
    pub size: usize,

    /// Parsed JSON body (if applicable)
    pub json: Option<serde_json::Value>,

    /// Raw body hash (SHA-256) for integrity
    pub hash: String,
}

/// Request body enum for different content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestBody {
    /// Plain text body
    Text(String),
    /// JSON body
    Json(serde_json::Value),
    /// Binary body
    Binary(Vec<u8>),
}

/// Additional request context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// TLS version used
    pub tls_version: Option<String>,

    /// TLS cipher suite
    pub tls_cipher: Option<String>,

    /// Client certificate fingerprint (if mTLS)
    pub client_cert_fingerprint: Option<String>,

    /// Geographic country code (from IP)
    pub geo_country: Option<String>,

    /// Geographic city (from IP)
    pub geo_city: Option<String>,

    /// ASN information
    pub asn: Option<u32>,

    /// ASN organization name
    pub asn_org: Option<String>,

    /// Whether IP is from a known datacenter
    pub is_datacenter: bool,

    /// Whether IP is a known proxy/VPN
    pub is_proxy: bool,

    /// Whether IP is a Tor exit node
    pub is_tor: bool,

    /// Request latency from edge to origin (ms)
    pub edge_latency_ms: Option<u32>,

    /// Cloudflare/CDN request ID (for correlation)
    pub cdn_request_id: Option<String>,
}
