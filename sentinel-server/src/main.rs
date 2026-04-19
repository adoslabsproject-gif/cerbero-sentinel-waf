// Copyright 2026 Nicola Cucurachi. Apache-2.0 license.
//! SENTINEL WAF Server
//!
//! HTTP server for SENTINEL Web Application Firewall.
//! Designed for high-performance AI agent security.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use sentinel_core::SentinelConfig;
use sentinel_server::{metrics, Sentinel};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Application state
struct AppState {
    sentinel: Arc<Sentinel>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing — log level from SENTINEL_LOG_LEVEL env var (default: warn)
    // Production: set SENTINEL_LOG_LEVEL=warn in PM2 config
    // Debug: set SENTINEL_LOG_LEVEL=debug or use RUST_LOG=sentinel=debug
    let sentinel_level = std::env::var("SENTINEL_LOG_LEVEL").unwrap_or_else(|_| "warn".to_string());
    let default_filter = format!("sentinel={sentinel_level},tower_http=warn");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.parse().unwrap()),
        )
        .json()
        .init();

    tracing::info!("Starting SENTINEL WAF Server");

    // Load configuration with environment overrides
    let mut config = SentinelConfig::default();

    // Override models path from environment
    if let Ok(models_path) = std::env::var("SENTINEL_MODELS_PATH") {
        config.neural.models_path = models_path;
    }

    // Create SENTINEL instance
    let sentinel = Arc::new(Sentinel::new(config)?);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "SENTINEL initialized"
    );

    // Check health
    let health = sentinel.health();
    tracing::info!(
        status = %health.status,
        edge_ready = health.edge_ready,
        neural_ready = health.neural_ready,
        behavior_ready = health.behavior_ready,
        response_ready = health.response_ready,
        "Health check passed"
    );

    // Create app state
    let state = Arc::new(AppState { sentinel });

    // Build router
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/metrics", get(metrics_handler))
        .route("/metrics/prometheus", get(prometheus_handler))
        .route("/analyze", post(analyze_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Bind to address — port from SENTINEL_PORT env or default 8080
    let port: u16 = std::env::var("SENTINEL_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!(%addr, %port, "SENTINEL WAF Server listening");

    // Start server
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check handler
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let health = state.sentinel.health();
    (StatusCode::OK, Json(health))
}

/// Stats handler
async fn stats_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.sentinel.stats();
    (StatusCode::OK, Json(stats))
}

/// Metrics handler (JSON format)
async fn metrics_handler() -> impl IntoResponse {
    let json = metrics::export_json();
    (StatusCode::OK, Json(json))
}

/// Prometheus metrics handler
async fn prometheus_handler() -> impl IntoResponse {
    let output = metrics::export_prometheus();
    (StatusCode::OK, output)
}

/// Request analysis payload
#[derive(serde::Deserialize)]
struct AnalyzeRequest {
    /// Client IP address
    client_ip: String,
    /// Request path
    path: String,
    /// HTTP method
    method: String,
    /// Request body (optional)
    body: Option<String>,
    /// Agent ID (optional)
    agent_id: Option<String>,
}

/// Analysis response
#[derive(serde::Serialize)]
#[allow(dead_code)]
struct AnalyzeResponse {
    /// Action to take
    action: String,
    /// Risk level
    risk_level: String,
    /// Additional details
    details: serde_json::Value,
}

/// Analyze a request
async fn analyze_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    // Parse client IP
    let client_ip = match payload.client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid client IP address"
                })),
            );
        }
    };

    // Build request
    let request = sentinel_core::Request {
        client_ip,
        path: payload.path,
        method: payload.method,
        body: payload.body.map(sentinel_core::RequestBody::Text),
        ..Default::default()
    };

    // Get agent ID if provided
    let agent_id = payload.agent_id.map(|id| sentinel_core::AgentId::new_from_string(&id));

    // Process request
    match state.sentinel.process(&request, agent_id.as_ref()).await {
        Ok(action) => {
            let (action_str, details) = match &action {
                sentinel_core::Action::Allow => ("allow", serde_json::json!({})),
                sentinel_core::Action::Block { reason, retry_after } => (
                    "block",
                    serde_json::json!({
                        "reason": reason,
                        "retry_after_secs": retry_after.map(|d| d.as_secs())
                    }),
                ),
                sentinel_core::Action::Challenge(challenge) => (
                    "challenge",
                    serde_json::json!({
                        "challenge_id": challenge.id,
                        "challenge_type": format!("{:?}", challenge.challenge_type),
                        "data": challenge.data
                    }),
                ),
                sentinel_core::Action::RateLimit { requests_per_minute } => (
                    "rate_limit",
                    serde_json::json!({
                        "requests_per_minute": requests_per_minute
                    }),
                ),
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "action": action_str,
                    "details": details
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e.to_string()
            })),
        ),
    }
}
