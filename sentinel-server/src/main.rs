//! SENTINEL WAF Server
//!
//! HTTP server for SENTINEL Web Application Firewall.
//! Designed for high-performance AI agent security.

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use sentinel_core::SentinelConfig;
use sentinel_server::{metrics, ProtectionLayer, Sentinel};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::trace::TraceLayer;

// LoRA-ready structured event channel (sentinel-events-YYYY-MM-DD.jsonl).
// Separato da PM2 stdout per training dataset Liara future.
mod lora_log;
mod sla_observability;
mod ledger_sync;
use lora_log::{emit_event, Detection, EventType, LoraEvent, ResponseAction, RequestInfo, Severity};
use sla_observability::SlaStore;
use sentinel_persistence::{AnomalyBaselinePayload, PortalClient, PortalClientConfig, ThreatPayload, ThreatSeverity};

/// Application state
struct AppState {
    sentinel: Arc<Sentinel>,
    /// Secret atteso per X-Sentinel-Secret header. Caricato UNA SOLA volta al
    /// boot e validato (>= 32 chars). MAI rileggere env runtime — un attaccante
    /// che riesca a sovrascrivere env (es. /proc/self/environ injection) NON
    /// puo\` disattivare il check.
    expected_secret: String,
    /// F7 (2026-06-02): client dedicato per persistere il ledger F5 recidivi
    /// in Postgres via portal. Separato da quello dentro ResponseLayer per
    /// non interferire con la pipeline ban esistente.
    ledger_portal_client: PortalClient,
    /// G19 (2026-06-02): SLA observability per-tenant (latency + action breakdown)
    sla_store: std::sync::Arc<SlaStore>,
    /// G13 wired (2026-06-02): cross-instance ledger sync via Redis pub/sub.
    /// Single-pod = `disabled` (no-op). Multi-pod = ban su pod-A → broadcast → DashMap update su pod-B/C.
    ledger_sync: ledger_sync::LedgerSyncStore,
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

    // G21.1 (2026-06-11): spike-breaker su TUTTI i ban path, pesato per
    // confidenza. Registrato PRIMA che il router accetti traffico.
    if !register_ban_spike_breaker(&sentinel) {
        tracing::error!("G21.1: ban spike breaker già registrato (set-once violato) — bug di boot");
        std::process::exit(2);
    }

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

    // HIGH (2026-05-29): SENTINEL_INTERNAL_SECRET OBBLIGATORIO al boot.
    // Pre-fix: validate_internal_secret ritornava true se env vuoto
    // ("dev mode"). Tipo / .env non caricato / deploy fresh → tutti gli
    // endpoint diventavano pubblici (analyze, bans/push, safe-mode/disable).
    // Fix: fail-fast al boot. Niente cammino di degrado silenzioso.
    let expected_secret = std::env::var("SENTINEL_INTERNAL_SECRET").unwrap_or_default();
    if expected_secret.len() < 32 {
        tracing::error!(
            secret_len = expected_secret.len(),
            "SENTINEL_INTERNAL_SECRET non impostato o troppo corto (richiesti >= 32 chars). Usa: openssl rand -hex 32"
        );
        std::process::exit(2);
    }

    // F7: PortalClient dedicato per ledger persistence (boot ledger reload + bump UPSERT)
    let ledger_portal_client = PortalClient::spawn(PortalClientConfig::from_env());

    // F7: boot reload del ledger F5 da Postgres → riempi DashMap in-memory
    // PRIMA che gli handler inizino a chiamare compute_escalated_ban_duration.
    // Idempotente: se portal non risponde / disabilitato → start a stato vuoto.
    if let Err(e) = bootstrap_offender_ledger(&ledger_portal_client).await {
        tracing::warn!(
            err = %e,
            "F7: boot reload offender ledger fallito — sentinel parte con ledger vuoto"
        );
    }

    // Boot reload della BASELINE ANOMALY da Postgres → il WAF non riparte cieco dopo i
    // restart (prima la baseline Welford era SOLO in RAM). Resiliente: portal giù /
    // disabilitato → start a freddo. Snapshot con schema-feature incompatibile scartati
    // dal BaselineStore (restore drop dim-mismatch).
    match ledger_portal_client.fetch_anomaly_baselines().await {
        Ok(payloads) => {
            let snaps: Vec<sentinel_behavior::anomaly_baseline::BaselineSnapshot> = payloads
                .into_iter()
                .filter_map(|p| {
                    serde_json::from_value(p.stats)
                        .ok()
                        .map(|stats| sentinel_behavior::anomaly_baseline::BaselineSnapshot { tenant: p.tenant, stats })
                })
                .collect();
            let n = snaps.len();
            sentinel.behavior().restore_anomaly_baselines(snaps);
            tracing::info!(loaded = n, "baseline anomaly restored from Postgres (sopravvive restart)");
        }
        Err(e) => tracing::warn!(err = %e, "boot reload baseline anomaly fallito — parte a freddo"),
    }

    // G13 wired (2026-06-02): cross-instance ledger sync.
    // ENABLED se SENTINEL_LEDGER_SYNC_REDIS_URL impostato (multi-pod deploy).
    // SENTINEL_POD_ID identifica univocamente questo pod (es. "eu-west-1-pod-2").
    // Single-pod (single binary, no replica) → tenere disabled.
    let ledger_sync = match std::env::var("SENTINEL_LEDGER_SYNC_REDIS_URL") {
        Ok(url) if !url.is_empty() => {
            let pod_id = std::env::var("SENTINEL_POD_ID")
                .unwrap_or_else(|_| format!("pod-{}", uuid::Uuid::now_v7().simple()));
            match ledger_sync::LedgerSyncStore::connect(&url, pod_id.clone()).await {
                Ok(store) => {
                    tracing::info!(pod_id = %pod_id, "G13: ledger sync enabled (multi-instance)");
                    store
                }
                Err(e) => {
                    tracing::warn!(err = %e, "G13: ledger sync connect fail — fallback disabled");
                    ledger_sync::LedgerSyncStore::disabled()
                }
            }
        }
        _ => {
            tracing::info!("G13: ledger sync disabled (SENTINEL_LEDGER_SYNC_REDIS_URL not set, single-pod mode)");
            ledger_sync::LedgerSyncStore::disabled()
        }
    };

    // G13 wired: spawn subscriber → riceve bump da altri pod e aggiorna ledger locale
    if ledger_sync.is_enabled() {
        let mut rx = ledger_sync.spawn_subscriber().await;
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Ok(ip) = msg.ip.parse::<std::net::IpAddr>() {
                    HONEYPOT_OFFENDER_LEDGER.insert(ip, (msg.ban_count, msg.last_banned_at_epoch_secs));
                    tracing::info!(
                        ip = %ip,
                        ban_count = msg.ban_count,
                        origin = %msg.origin_pod,
                        "G13: ledger updated from remote pod"
                    );
                }
            }
        });
    }

    // Create app state
    let state = Arc::new(AppState {
        sentinel,
        expected_secret,
        ledger_portal_client,
        sla_store: std::sync::Arc::new(SlaStore::new()),
        ledger_sync,
    });

    // Flush periodico della BASELINE ANOMALY: ogni 60s invia al Portal i soli segmenti
    // DIRTY (drain incrementale) → la baseline appresa diventa DURABILE. Fire-and-forget
    // (no blocco hot-path); send_anomaly_baselines è no-op su batch vuoto / client disabilitato.
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let batch: Vec<AnomalyBaselinePayload> = st
                    .sentinel
                    .behavior()
                    .drain_anomaly_baselines()
                    .into_iter()
                    .filter_map(|s| {
                        serde_json::to_value(&s.stats)
                            .ok()
                            .map(|stats| AnomalyBaselinePayload { tenant: s.tenant, stats })
                    })
                    .collect();
                st.ledger_portal_client.send_anomaly_baselines(batch);
            }
        });
    }

    // F6+F9 (2026-06-02): background task per persistere layer3 detections in
    // JSONL LoRA-ready. Drain events_since(last_seen) ogni 30s e li scrive
    // come EventType::ThreatClassified (NO duplicato dei ban gia\` emessi
    // sync).
    //
    // F9: persistenza cursor in `/opt/zeliai/shared/sentinel-lora-cursor`
    // via atomic write (tempfile + rename). Boot: legge cursor → riparte
    // dall'event_id ultimo flushato → NIENTE eventi duplicati nella
    // pipeline LoRA cross-restart.
    {
        let state_for_flush = state.clone();
        let cursor_path = std::path::PathBuf::from(
            std::env::var("SENTINEL_LORA_CURSOR_PATH")
                .unwrap_or_else(|_| "/opt/zeliai/shared/sentinel-lora-cursor".to_string()),
        );

        // Boot: leggi cursor persistito (parsing tollerante: file inesistente
        // o corrotto = restart from 0, log warn)
        let initial_last_seen: u64 = match std::fs::read_to_string(&cursor_path) {
            Ok(s) => s.trim().parse::<u64>().unwrap_or_else(|e| {
                tracing::warn!(
                    path = %cursor_path.display(),
                    err = %e,
                    "F9: cursor file corrotto, riparto da 0"
                );
                0
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    path = %cursor_path.display(),
                    "F9: nessun cursor pre-esistente, primo avvio (last_seen=0)"
                );
                0
            }
            Err(e) => {
                tracing::warn!(
                    path = %cursor_path.display(),
                    err = %e,
                    "F9: errore lettura cursor, riparto da 0"
                );
                0
            }
        };
        tracing::info!(
            initial_last_seen = initial_last_seen,
            cursor_path = %cursor_path.display(),
            "F9: LoRA cursor caricato"
        );

        tokio::spawn(async move {
            let mut last_seen: u64 = initial_last_seen;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let events = state_for_flush.sentinel.behavior().drain_events_since(last_seen);
                if events.is_empty() {
                    continue;
                }
                let mut new_last_seen = last_seen;
                for d in events.iter() {
                    new_last_seen = new_last_seen.max(d.event_id);
                    let ip: std::net::IpAddr = match d.ip.parse() {
                        Ok(ip) => ip,
                        Err(_) => continue,
                    };
                    let geo = state_for_flush.sentinel.edge().ip_intel().lookup_country(ip);
                    let asn = state_for_flush.sentinel.edge().ip_intel().lookup_asn(ip);
                    let sev = if d.severity_score >= 0.85 {
                        Severity::High
                    } else if d.severity_score >= 0.5 {
                        Severity::Warn
                    } else {
                        Severity::Info
                    };
                    let mut ev = LoraEvent::new(EventType::ThreatClassified, sev, "sentinel-server")
                        .with_client(&d.ip);
                    ev.client.country = geo;
                    if let Some(a) = asn.as_ref() {
                        ev.client.asn = Some(a.asn);
                        ev.client.asn_org = Some(a.org.clone());
                        ev.client.is_datacenter = Some(a.is_hosting);
                    }
                    ev.detection = Some(Detection {
                        trigger_type: Some(d.rule_id.to_string()),
                        trigger_value: Some(format!("evidence={}/{}sec", d.evidence_count, d.time_window_sec)),
                        hit_count: Some(d.evidence_count as u32),
                        classifier_score: Some(d.severity_score as f32),
                        matched_patterns: Some(vec![d.human_description.clone()]),
                        ..Default::default()
                    });
                    ev.response_action = Some(ResponseAction {
                        action_taken: Some(d.decision_label.to_string()),
                        ban_duration_secs: None,
                        ban_reason: None,
                        escalation_level: None,
                    });
                    emit_event(ev);
                }

                // F9: persisti il cursor DOPO che tutti gli eventi del batch
                // sono stati emessi (at-least-once delivery — preferiamo
                // un duplicato a un evento perso).
                if new_last_seen > last_seen {
                    if let Err(e) = atomic_write_cursor(&cursor_path, new_last_seen) {
                        tracing::error!(
                            err = %e,
                            cursor_path = %cursor_path.display(),
                            new_last_seen = new_last_seen,
                            "F9: scrittura cursor fallita — pipeline LoRA potrebbe duplicare al prossimo restart"
                        );
                    }
                    last_seen = new_last_seen;
                }

                tracing::debug!(
                    flushed_count = events.len(),
                    last_event_id = last_seen,
                    "F6+F9: drained Layer 3 events to LoRA JSONL + cursor persisted"
                );
            }
        });
    }

    // Build router (v2.0.0: added safe-mode toggle).
    //
    // HIGH (2026-05-29):
    //  - DefaultBodyLimit 64 KiB su tutto il router: gli /analyze ricevono
    //    payload {client_ip, path, method, body, agent_id} con body fino a
    //    qualche KB max. 64KiB e\` 10x buffer per worst-case. Anti-DoS body
    //    gigante (default Axum 2MiB).
    //  - ConcurrencyLimit 256 concurrent requests: defense-in-depth oltre
    //    loopback-only + secret. Saturando questo cap, le request extra
    //    aspettano un slot invece di forkare task tokio illimitati.
    // Clone per il graceful-shutdown PRIMA che `.with_state(state)` consumi `state`.
    let shutdown_state = state.clone();
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/stats", get(stats_handler))
        .route("/metrics", get(metrics_handler))
        .route("/metrics/prometheus", get(prometheus_handler))
        .route("/analyze", post(analyze_handler))
        .route("/analyze/content", post(analyze_content_handler))
        .route("/honeypot/hit", post(honeypot_hit_handler))
        .route("/response/observed", post(response_observed_handler))
        .route("/events/since/{since_id}", get(events_since_handler))
        .route("/sla", get(sla_handler))
        .route("/sla/top/{n}", get(sla_top_handler))
        .route("/bans/push", post(ban_push_handler))
        .route("/bans/sync", post(ban_sync_handler))
        .route("/bans/active", get(bans_active_handler))
        .route("/defense-mode", get(defense_mode_handler))
        .route("/safe-mode", get(safe_mode_status_handler))
        .route("/safe-mode/enable", post(safe_mode_enable_handler))
        .route("/safe-mode/disable", post(safe_mode_disable_handler))
        .route("/safe-mode/layer/{layer}/enable", post(safe_mode_layer_enable_handler))
        .route("/safe-mode/layer/{layer}/disable", post(safe_mode_layer_disable_handler))
        // HIGH 2026-05-29 hardening layers:
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(ConcurrencyLimitLayer::new(256))
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

    // Start server con GRACEFUL SHUTDOWN: su SIGTERM/Ctrl-C facciamo un flush FINALE
    // (bloccante) della baseline anomaly prima di uscire → un restart/deploy non perde
    // fino a 60s di apprendimento (il flush periodico gira solo ogni 60s).
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_state))
        .await?;

    Ok(())
}

/// Attende SIGTERM (deploy/PM2) o Ctrl-C, poi esegue il FLUSH FINALE bloccante della
/// baseline anomaly. È il complemento del flush periodico 60s: senza, ogni restart
/// perde l'apprendimento dall'ultimo tick. `snapshot_anomaly_baselines()` cattura lo
/// stato COMPLETO di ogni tenant (non solo i dirty), e `..._blocking` AWAITA il POST
/// prima che il processo esca.
async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(err = %e, "[SHUTDOWN] handler SIGTERM non installabile");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::warn!("[SHUTDOWN] segnale ricevuto → flush finale baseline anomaly");
    let batch: Vec<AnomalyBaselinePayload> = state
        .sentinel
        .behavior()
        .snapshot_anomaly_baselines()
        .into_iter()
        .filter_map(|s| {
            serde_json::to_value(&s.stats)
                .ok()
                .map(|stats| AnomalyBaselinePayload { tenant: s.tenant, stats })
        })
        .collect();
    let n = batch.len();
    match state
        .ledger_portal_client
        .send_anomaly_baselines_blocking(batch)
        .await
    {
        Ok(()) => tracing::info!(count = n, "[SHUTDOWN] flush finale baseline ok"),
        Err(e) => tracing::error!(err = %e, count = n, "[SHUTDOWN] flush finale baseline FALLITO"),
    }
}

/// Health check handler
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let health = state.sentinel.health();
    (StatusCode::OK, Json(health))
}

/// Stats handler — N3 audit (2026-05-29): auth required (counter exposure
/// = recon info for an attacker with foothold). Bind 127.0.0.1 mitiga al
/// 95% ma defense-in-depth: stesso gate degli altri endpoint mutativi.
async fn stats_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        )
            .into_response();
    }
    let stats = state.sentinel.stats();
    (StatusCode::OK, Json(stats)).into_response()
}

/// Metrics handler (JSON format) — N3 audit: auth required.
async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        )
            .into_response();
    }
    let json = metrics::export_json();
    (StatusCode::OK, Json(json)).into_response()
}

/// Prometheus metrics handler — N3 audit: auth required.
///
/// Scrape config Prometheus deve includere `Authorization` o
/// `X-Sentinel-Secret` header (configurabile via `metrics_path` +
/// `authorization` block del scrape_config Prometheus).
async fn prometheus_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, "Forbidden".to_string()).into_response();
    }
    let output = metrics::export_prometheus();
    (StatusCode::OK, output).into_response()
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
    /// Whether this IP has triggered honeypot before (server-computed, never from client)
    honeypot_triggered: Option<bool>,
    /// HTTP request headers forwarded from the calling proxy (portal/runtime).
    /// MUST include `x-ja3-hash`, `x-ja4`, `x-tls-protocol`, `x-tls-cipher`,
    /// `x-http-version`, `x-tls-greased`, `x-http2-fingerprint` when nginx-ssl-fingerprint
    /// module is active. Without these, JA3 blocklist + UA-mismatch detection
    /// degrades gracefully (Section A10). Keys MUST be lowercased by the caller.
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
    /// Categoria logica del check (es. "llm_prompt"). Permette al response
    /// handler di trattare il traffico LLM interno autenticato senza ban/block
    /// da falso positivo del content classifier.
    #[serde(default)]
    category: Option<String>,
}

/// Internal auth secret validation for all non-health endpoints.
///
/// HIGH (2026-05-29): timing-safe constant-time compare per evitare timing
/// side-channel sull'header (CPU cache + branch prediction sui byte mismatch).
/// Confronto byte-by-byte con accumulator XOR senza early-exit.
fn validate_internal_secret(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let header = match headers.get("x-sentinel-secret") {
        Some(v) => v.as_bytes(),
        None => return false,
    };
    let expected = state.expected_secret.as_bytes();
    if header.len() != expected.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..expected.len() {
        diff |= header[i] ^ expected[i];
    }
    diff == 0
}

/// Analyze a request — auth required
async fn analyze_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        );
    }

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

    // Build request headers map.
    //
    // Priority:
    //   1. Forwarded headers from caller (ja3/ja4/tls-*/http-version/...) — needed
    //      by EdgeShield ja3_blocklist + ja3 UA-mismatch detector + http2 fingerprint.
    //   2. Server-computed honeypot_triggered flag — added LAST so client cannot spoof it.
    //
    // Allowlist filter: accept ONLY known security-relevant headers. Prevents
    // client from injecting arbitrary headers that could interfere with analysis.
    // Keys are already lowercased per AnalyzeRequest contract.
    const ALLOWED_FORWARDED_HEADERS: &[&str] = &[
        "x-ja3",
        "x-ja3-hash",
        "x-ja4",
        "x-tls-protocol",
        "x-tls-cipher",
        "x-tls-greased",
        "x-http-version",
        "x-http2-fingerprint",
        "user-agent",
        "accept-language",
        "referer",
        "origin",
        "cf-connecting-ip",
        "cf-ipcountry",
        "cf-ray",
    ];
    let mut headers_map = std::collections::HashMap::new();
    for (k, v) in &payload.headers {
        let key_lc = k.to_lowercase();
        if ALLOWED_FORWARDED_HEADERS.contains(&key_lc.as_str()) {
            headers_map.insert(key_lc, v.clone());
        }
    }
    if payload.honeypot_triggered == Some(true) {
        headers_map.insert("x-honeypot-triggered".to_string(), "true".to_string());
    }

    let request = sentinel_core::Request {
        client_ip,
        path: payload.path,
        method: payload.method,
        body: payload.body.map(sentinel_core::RequestBody::Text),
        headers: headers_map,
        category: payload.category,
        ..Default::default()
    };

    // Get agent ID if provided
    let agent_id = payload.agent_id.map(|id| sentinel_core::AgentId::new_from_string(&id));

    // Process request
    let analyze_start = std::time::Instant::now();
    match state.sentinel.process(&request, agent_id.as_ref()).await {
        Ok(decision) => {
            let risk_kind = sla_observability::RiskKind::from(decision.risk);
            let action = decision.action;
            let latency_us = analyze_start.elapsed().as_micros() as u64;
            // G19 (2026-06-02): record SLA per-tenant. Tenant ID = client_ip
            // come placeholder finché non si mappa workspace_id.
            let action_kind = match &action {
                sentinel_core::Action::Allow => sla_observability::ActionKind::Allow,
                sentinel_core::Action::Challenge(_) => sla_observability::ActionKind::Challenge,
                sentinel_core::Action::Block { .. } => sla_observability::ActionKind::Block,
                sentinel_core::Action::RateLimit { .. } => sla_observability::ActionKind::RateLimit,
            };
            // Risk level: livello effettivo calcolato dai layer (edge/neural/
            // behavioral) e propagato via Decision — non più placeholder None.
            state.sla_store.record(
                payload.client_ip.clone(),
                latency_us,
                action_kind,
                risk_kind,
            );

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

/// POST /bans/push — Single ban push from TS BanService
async fn ban_push_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<sentinel_server::api::BanPushRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    let api = sentinel_server::api::SentinelApi::new(state.sentinel.clone());
    match api.push_ban(payload).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::json!(resp))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

/// POST /bans/sync — Full ban sync from TS BanService
async fn ban_sync_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<sentinel_server::api::BanSyncRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    let api = sentinel_server::api::SentinelApi::new(state.sentinel.clone());
    let resp = api.sync_bans(payload).await;
    (StatusCode::OK, Json(serde_json::json!(resp)))
}

/// GET /bans/active — List all active bans in Rust
async fn bans_active_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    let api = sentinel_server::api::SentinelApi::new(state.sentinel.clone());
    let resp = api.active_bans().await;
    (StatusCode::OK, Json(serde_json::json!(resp)))
}

// ─── Content Analysis Endpoint (LLM Output Screening) ────────────────────────

/// Request payload for /analyze/content
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct AnalyzeContentRequest {
    /// The LLM output content to screen
    content: String,
    /// Optional context for analysis
    context: Option<ContentAnalysisContext>,
}

#[derive(serde::Deserialize)]
struct ContentAnalysisContext {
    /// User role (e.g., "marketplace_anonymous", "admin")
    #[allow(dead_code)]
    user_role: Option<String>,
    /// Whether the content includes tool output (soft mode)
    #[allow(dead_code)]
    is_tool_output: Option<bool>,
}

/// POST /analyze/content — Screen LLM output before delivery to client
async fn analyze_content_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AnalyzeContentRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        );
    }

    if payload.content.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "is_malicious": false,
                "score": 0.0,
                "model_used": "none",
                "patterns": [],
                "recommendation": "allow"
            })),
        );
    }

    match state.sentinel.analyze_content(&payload.content).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))),
        Err(e) => {
            tracing::error!(error = %e, "Content analysis failed");
            // Graceful degradation: allow on failure (don't block users because Sentinel had an error)
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "is_malicious": false,
                    "score": 0.0,
                    "model_used": "error",
                    "patterns": [],
                    "recommendation": "allow",
                    "error": e.to_string()
                })),
            )
        }
    }
}

// ─── Defense Mode Endpoint (WI-11) ────────────────────────────────────────────

/// GET /defense-mode — Defense mode status
async fn defense_mode_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        );
    }

    let status = state.sentinel.defense_status();
    (StatusCode::OK, Json(serde_json::json!(status)))
}

// ─── Honeypot Endpoint ────────────────────────────────────────────────────────

/// Request payload for /honeypot/hit
#[derive(serde::Deserialize)]
struct HoneypotHitRequest {
    /// Client IP address that hit the honeypot
    ip: String,
    /// The honeypot endpoint that was accessed
    endpoint: String,
    /// User-Agent header
    user_agent: Option<String>,
    /// Forwarded headers (lowercase keys) — JA3/JA4/TLS context.
    /// If `x-ja3-hash` matches ja3_blocklist → ban INSTANT (no threshold wait).
    /// If JA3 indicates browser but UA indicates scanner → ban INSTANT (mismatch).
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
}

/// Honeypot hit tracking (in-memory, persistent within Sentinel process lifetime)
static HONEYPOT_TRACKER: once_cell::sync::Lazy<
    dashmap::DashMap<std::net::IpAddr, Vec<HoneypotEvent>>,
> = once_cell::sync::Lazy::new(dashmap::DashMap::new);

/// F5 (2026-06-02): repeat-offender ledger.
/// Conta quante volte un IP è stato bannato per honeypot. Survive il
/// window 24h e l'expire del ban — escala automaticamente.
/// Schema: (ban_count, last_banned_at_epoch_secs, retention_days)
static HONEYPOT_OFFENDER_LEDGER: once_cell::sync::Lazy<
    dashmap::DashMap<std::net::IpAddr, (u32, u64)>,
> = once_cell::sync::Lazy::new(dashmap::DashMap::new);

#[allow(dead_code)]
struct HoneypotEvent {
    endpoint: String,
    user_agent: Option<String>,
    timestamp: std::time::Instant,
}

/// Fase ML (2026-07-07): timing REALE dagli hit del tracker per il vettore feature.
/// burst = hit negli ultimi 60s; stddev = deviazione std dei delta (secondi) fra hit
/// consecutivi. <3 hit → stddev 0.0 (onesto: non stimabile).
fn honeypot_timing(ip: std::net::IpAddr) -> (f32, f32) {
    let Some(events) = HONEYPOT_TRACKER.get(&ip) else { return (0.0, 0.0) };
    let now = std::time::Instant::now();
    let burst = events
        .iter()
        .filter(|e| now.duration_since(e.timestamp).as_secs() < 60)
        .count() as f32;
    if events.len() < 3 {
        return (burst, 0.0);
    }
    // età (secondi) di ogni hit, ordinate → delta fra hit consecutivi
    let mut ages: Vec<f64> = events
        .iter()
        .map(|e| now.duration_since(e.timestamp).as_secs_f64())
        .collect();
    ages.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let deltas: Vec<f64> = ages.windows(2).map(|w| w[1] - w[0]).collect();
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    let var = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
    (burst, var.sqrt() as f32)
}

/// Fase ML (2026-07-07): vettore RAW 18-feature per i ban HONEYPOT — prima questo
/// path (≈90% dei threat persistiti) mandava `ml_features=None` → il dataset del
/// meta threat_classifier cresceva solo dalle escalation (~righe/settimana) e il
/// gate auto-train (≥500 etichette) non sarebbe MAI scattato. Valori onesti:
/// risk/confidence 0.99 (= classifier_score emesso per il trigger honeypot),
/// burst/stddev dai timestamp reali del tracker, anomaly NON MISURATA (nessun
/// behavior layer su questo fast-path), is_tor/is_proxy non misurati (ip_intel
/// non li espone). Stringhe categoriche = quelle del ban (`honeypot_scan`,
/// `sentinel_honeypot`).
///
/// I punteggi finiscono nel record salvato ma NON nel vettore del modello: sono
/// assegnati dalla stessa regola che etichetta la riga (vedi LABEL_DERIVED_FEATURES).
fn build_honeypot_ml_features(
    state: &AppState,
    ip: std::net::IpAddr,
    payload: &HoneypotHitRequest,
) -> Option<serde_json::Value> {
    let (path, query) = match payload.endpoint.split_once('?') {
        Some((p, q)) => (p, q),
        None => (payload.endpoint.as_str(), ""),
    };
    // Lookup fallito = "non lo so", NON "non è un datacenter": il buco viaggia fino al
    // trainer come null e il modello impara da sé cosa farne.
    let is_dc = state
        .sentinel
        .edge()
        .ip_intel()
        .lookup_asn(ip)
        .map(|a| a.is_hosting);
    let (burst_score, inter_request_stddev) = honeypot_timing(ip);
    let now = chrono::Utc::now();
    let input = sentinel_neural::threat_features::ThreatFeatureInput {
        risk_score: 0.99,
        confidence: 0.99,
        hour_of_day: chrono::Timelike::hour(&now) as u8,
        day_of_week: chrono::Datelike::weekday(&now).num_days_from_monday() as u8,
        is_datacenter: is_dc,
        // ip_intel non espone questi segnali su nessun percorso → non misurati.
        is_tor: None,
        is_proxy: None,
        path,
        user_agent: payload.user_agent.as_deref().unwrap_or(""),
        query,
        severity_numeric: 3, // High — coerente con la severity del ban honeypot
        burst_score: Some(burst_score),
        inter_request_stddev: Some(inter_request_stddev),
        // ⚠️ NON 0.0: l'honeypot è un fast-path che non attraversa il layer neurale,
        // quindi l'anomalia non è stata calcolata. Scriverla zero significava dichiarare
        // "nessuna anomalia" su OGNI attacco honeypot, mentre i benigni davvero misurati
        // arrivavano a ~0.93 — il segnale risultava rovesciato.
        anomaly_score: None,
        threat_type: "honeypot_scan",
        detection_source: "sentinel_honeypot",
        request_method: "GET",
    };
    serde_json::to_value(sentinel_neural::threat_features::to_raw_record(&input)).ok()
}

/// Vettore RAW per una detection di SLOW-ENUMERATION (zona grigia, 2026-08-02).
///
/// È il caso più prezioso per il training e finora era l'unico completamente assente:
/// due enumerazioni con lo stesso punteggio possono essere un aggregatore di feed che
/// cerca `/ads.txt` e `/atom.xml`, oppure qualcuno che raccoglie `/.cursorrules` e
/// `/.aider.conf.yml` per rubare configurazioni. Le regole non sanno distinguerle; il
/// contenuto sì. Senza vettore, nemmeno un'etichetta umana perfetta sarebbe servita a
/// qualcosa — la riga non era esportabile.
///
/// Cosa si sa qui e cosa no: il detector osserva la RISPOSTA, quindi il path sondato e
/// l'ora sono reali, mentre i segnali comportamentali e l'anomalia neurale non vengono
/// calcolati su questo percorso → `None`, mai zeri di comodo. `burst_score` fa eccezione
/// ed è REALE: il numero di path distinti nella finestra È una misura di raffica, presa
/// dal detector stesso.
fn build_enumeration_ml_features(
    ip: std::net::IpAddr,
    path: &str,
    distinct_paths: usize,
) -> Option<serde_json::Value> {
    let _ = ip; // l'ip_intel non è raggiungibile da questo handler → is_* restano None
    let now = chrono::Utc::now();
    let (clean_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    let input = sentinel_neural::threat_features::ThreatFeatureInput {
        risk_score: 0.6,
        confidence: 0.6,
        hour_of_day: chrono::Timelike::hour(&now) as u8,
        day_of_week: chrono::Datelike::weekday(&now).num_days_from_monday() as u8,
        is_datacenter: None,
        is_tor: None,
        is_proxy: None,
        path: clean_path,
        // Il detector di enumeration lavora sui path, non conserva l'UA della richiesta.
        user_agent: "",
        query,
        severity_numeric: 2, // Medium — coerente con la severity del record
        // Path distinti nella finestra: è una raffica misurata, non una stima.
        burst_score: Some(distinct_paths as f32),
        inter_request_stddev: None,
        anomaly_score: None,
        threat_type: "slow_enumeration",
        detection_source: "sentinel_enumeration",
        request_method: "GET",
    };
    serde_json::to_value(sentinel_neural::threat_features::to_raw_record(&input)).ok()
}

/// Auto-ban threshold: 3+ honeypot hits from same IP → ban for 7 days
const HONEYPOT_BAN_THRESHOLD: usize = 3;
/// Ban duration for FIRST honeypot ban: 7 days
const HONEYPOT_BAN_DURATION: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 60 * 60);
/// F5: SECOND ban (recidive < 30 days from first): 30 days
const HONEYPOT_BAN_DURATION_2ND: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 60 * 60);
/// F5: THIRD+ ban (chronic offender): 365 days (1 year, max practical)
const HONEYPOT_BAN_DURATION_3RD: std::time::Duration = std::time::Duration::from_secs(365 * 24 * 60 * 60);
/// F5: ledger retention — dimentica un IP se non offende per 90 giorni
const HONEYPOT_OFFENDER_LEDGER_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;
/// Only count hits within the last 24 hours for threshold calculation
const HONEYPOT_WINDOW: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// G21 (2026-06-02, riscritto G21.1 2026-06-11): auto-rollback ban spike —
/// se i ban A BASSA CONFIDENZA per minuto superano questo numero, attiviamo
/// safe-mode (Allow tutto tranne hard WAF) + alert HIGH. Indica un cascade
/// falso-positivo (CRS pattern troppo largo, behavioral threshold sballato)
/// che rischia di bannare utenti VERI = outage.
///
/// G21.1: i ban ad ALTA confidenza (honeypot, known-attack-path, JA3/JA4
/// blocklist, manual) NON alimentano il counter: un flood di scanner è un
/// attacco reale e deve incontrare PIÙ difesa, non spegnerla. Pre-fix il
/// breaker era weaponizzabile: 100 ban corretti/min → blocking OFF sotto
/// attacco (incident 2026-06-11, flood di 212 probe /.env).
const BAN_SPIKE_THRESHOLD_PER_MIN: usize = 100;
/// G21: sliding window per il ban spike counter (60 secondi)
const BAN_SPIKE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// G21.2: counter ban recenti PER-LAYER — ogni layer ha la sua finestra, così
/// un cascade attribuibile a un layer non viene "diluito" dai ban degli altri,
/// e il breaker sospende SOLO il layer che cascada (vedi register_ban_spike_breaker).
static BAN_SPIKE_COUNTER: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<ProtectionLayer, std::collections::VecDeque<std::time::Instant>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
/// G21.2: ultimo trigger PER-LAYER (cooldown 5min anti alert-spam, per layer).
static BAN_SPIKE_TRIGGERED_AT: once_cell::sync::Lazy<
    parking_lot::Mutex<std::collections::HashMap<ProtectionLayer, std::time::Instant>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

/// G21.2 (2026-06-11): mappa BanReason → layer di protezione attribuibile, per
/// lo spike-breaker. `None` = ban ad ALTA confidenza (evidenza deterministica
/// o decisione umana): NON alimenta nessun counter e non può MAI sospendere un
/// layer — un flood di scanner deve incontrare PIÙ difesa, non spegnerla
/// (incident 2026-06-11). `Some(layer)` = ban euristico/statistico: un cascade
/// di questi sospende SOLO quel layer.
///
/// Match esaustivo DELIBERATO (no `_`): un nuovo BanReason deve dichiarare
/// esplicitamente layer/confidenza, pena build rosso.
///
/// Nota onesta su `CriticalRisk`: nasce dal punteggio COMBINATO che supera la
/// soglia Critical, quindi non è attribuibile a un singolo layer con certezza.
/// Lo mappiamo a `Neural` perché nella stragrande maggioranza dei cascade il
/// driver è il content/web-attack classifier (l'unico che ha già prodotto un
/// cascade reale — incident llm_prompt 2026-06-06). Le reason ESPLICITE
/// (4xx-burst, rate-limit, prompt-injection) sono invece 1:1 col loro layer.
fn ban_spike_layer(reason: sentinel_response::BanReason) -> Option<ProtectionLayer> {
    use sentinel_response::BanReason;
    match reason {
        // Alta confidenza: nessun layer, nessun counter, nessun rollback.
        BanReason::HoneypotTriggered | BanReason::Manual => None,
        // Edge: rate-limit è un segnale del layer 1.
        BanReason::RateLimitExceeded => Some(ProtectionLayer::Edge),
        // Neural: classifier di contenuto / web-attack / prompt injection.
        BanReason::PromptInjection | BanReason::CriticalRisk => Some(ProtectionLayer::Neural),
        // Behavioral: 4xx-burst, attacco coordinato, challenge fallita.
        BanReason::Behavioral4xxBurst
        | BanReason::CoordinatedAttack
        | BanReason::ChallengeFailed => Some(ProtectionLayer::Behavioral),
    }
}

/// G21.2: record nuovo ban a bassa confidenza nel counter del SUO layer.
/// Ritorna (count_del_layer, should_trigger). Sliding window 60s per-layer +
/// cooldown 5min per-layer.
fn record_ban_for_spike_check(layer: ProtectionLayer) -> (usize, bool) {
    let now = std::time::Instant::now();
    let mut counters = BAN_SPIKE_COUNTER.lock();
    let counter = counters.entry(layer).or_default();
    // Cleanup expired (per il layer corrente).
    while let Some(t) = counter.front() {
        if now.duration_since(*t) > BAN_SPIKE_WINDOW {
            counter.pop_front();
        } else {
            break;
        }
    }
    counter.push_back(now);
    let count = counter.len();
    drop(counters);

    if count >= BAN_SPIKE_THRESHOLD_PER_MIN {
        let mut last = BAN_SPIKE_TRIGGERED_AT.lock();
        let already = last
            .get(&layer)
            .map(|t| now.duration_since(*t).as_secs() < 300) // 5min cooldown alert
            .unwrap_or(false);
        if !already {
            last.insert(layer, now);
            return (count, true);
        }
    }
    (count, false)
}

/// G21.2: registra lo spike-breaker come observer su BanManager — il punto di
/// convergenza di TUTTI i ban path (honeypot handler, 4xx-burst, CriticalRisk
/// dentro determine_action, manual API). Un cascade di ban a bassa confidenza
/// attribuibile a un layer sospende SOLO quel layer (granulare): edge/neural/
/// honeypot continuano a bloccare. I ban ad alta confidenza non lo triggerano.
///
/// Weak<Sentinel> per evitare il ciclo Arc (Sentinel → response → ban_manager
/// → closure → Sentinel).
fn register_ban_spike_breaker(sentinel: &Arc<Sentinel>) -> bool {
    let weak = Arc::downgrade(sentinel);
    sentinel.response().set_ban_notifier(Box::new(move |ip, reason| {
        let Some(layer) = ban_spike_layer(reason) else { return };
        let (spike_count, should_trigger) = record_ban_for_spike_check(layer);
        if !should_trigger {
            return;
        }
        let Some(sentinel) = weak.upgrade() else { return };
        // Granulare: sospende SOLO il layer che cascada.
        let transitioned = sentinel.suspend_layer(layer);
        tracing::error!(
            ban_count_per_min = spike_count,
            threshold = BAN_SPIKE_THRESHOLD_PER_MIN,
            layer = layer.as_str(),
            last_ban_reason = %reason,
            transition = transitioned,
            "G21.2: BAN SPIKE su layer '{}' (cascade low-confidence) — layer sospeso, \
             gli altri layer + hard-WAF restano ATTIVI. AZIONE: verifica /admin/sentinel-live \
             + riattiva il layer quando la regola è sistemata.",
            layer.as_str(),
        );
        // Emit LoRA event per audit trail
        let mut spike_event = LoraEvent::new(EventType::ThreatClassified, Severity::High, "sentinel-server")
            .with_client(&ip.to_string());
        spike_event.detection = Some(Detection {
            trigger_type: Some("g21.ban_spike_auto_rollback".to_string()),
            trigger_value: Some(format!("{spike_count} low-confidence bans/60s su layer {}", layer.as_str())),
            hit_count: Some(spike_count as u32),
            classifier_score: Some(0.99),
            matched_patterns: Some(vec![format!(
                "G21.2 BAN SPIKE: {} ban a bassa confidenza negli ultimi 60s sul layer '{}' (soglia {}). \
                 Safe-mode GRANULARE: sospeso solo questo layer, gli altri restano attivi.",
                spike_count, layer.as_str(), BAN_SPIKE_THRESHOLD_PER_MIN,
            )]),
            ..Default::default()
        });
        spike_event.response_action = Some(ResponseAction {
            action_taken: Some(format!("safe_mode_layer_suspended:{}", layer.as_str())),
            ban_duration_secs: None,
            ban_reason: Some(format!("auto-rollback ban spike (cascade {} layer)", layer.as_str())),
            escalation_level: Some(9),
        });
        emit_event(spike_event);
    }))
}

/// F5: epoch seconds helper for repeat-offender ledger.
fn epoch_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// F5: ritorna la durata ban appropriata in base alla recidiva.
/// Aggiorna il ledger atomicamente (count++ + timestamp).
fn compute_escalated_ban_duration(ip: std::net::IpAddr) -> (std::time::Duration, u32) {
    let now = epoch_now_secs();
    let mut entry = HONEYPOT_OFFENDER_LEDGER.entry(ip).or_insert((0, 0));
    // Forget recidive se silenzioso per RETENTION_SECS (escalation reset)
    if now.saturating_sub(entry.1) > HONEYPOT_OFFENDER_LEDGER_RETENTION_SECS {
        entry.0 = 0;
    }
    entry.0 += 1;
    entry.1 = now;
    let count = entry.0;
    let duration = match count {
        1 => HONEYPOT_BAN_DURATION,
        2 => HONEYPOT_BAN_DURATION_2ND,
        _ => HONEYPOT_BAN_DURATION_3RD,
    };
    (duration, count)
}

/// F7 (2026-06-02): boot-time reload del ledger F5 da Postgres via portal.
/// Idempotent: ricarica `HONEYPOT_OFFENDER_LEDGER` con le entry dal DB.
/// Resilient: se portal/secret non config → ritorna Ok con 0 entry; se HTTP
/// fallisce → propaga errore (main.rs logga warn ma continua boot con
/// ledger vuoto).
async fn bootstrap_offender_ledger(
    client: &sentinel_persistence::PortalClient,
) -> Result<(), sentinel_persistence::PersistError> {
    let entries = client.fetch_offender_ledger().await?;
    let count = entries.len();
    for e in entries {
        if let Ok(ip) = e.ip_address.parse::<std::net::IpAddr>() {
            HONEYPOT_OFFENDER_LEDGER.insert(ip, (e.ban_count, e.last_banned_at_epoch_secs));
        }
    }
    tracing::info!(
        loaded_entries = count,
        "F7: offender ledger restored from Postgres (sopravvive restart)"
    );
    Ok(())
}

// ─── Safe Mode Endpoints (N5) ─────────────────────────────────────────────────

/// GET /safe-mode — Check safe mode status
async fn safe_mode_status_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    let active = state.sentinel.is_safe_mode_active();
    let suspended = state.sentinel.suspended_layers();
    (StatusCode::OK, Json(serde_json::json!({
        "safe_mode_active": active,
        "suspended_layers": suspended,
        "available_layers": ["edge", "neural", "behavioral"],
        "description": if active {
            "Uno o più layer in safe-mode (blocking soft sospeso, hard WAF attiva). Vedi suspended_layers."
        } else {
            "Normal operation. All blocking rules active."
        }
    })))
}

/// POST /safe-mode/layer/{layer}/enable — sospende UN solo layer (granulare).
async fn safe_mode_layer_enable_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(layer): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let Some(l) = ProtectionLayer::parse(&layer) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Unknown layer", "available_layers": ["edge", "neural", "behavioral"]
        })));
    };
    state.sentinel.suspend_layer(l);
    (StatusCode::OK, Json(serde_json::json!({
        "layer": l.as_str(),
        "suspended": true,
        "suspended_layers": state.sentinel.suspended_layers(),
        "message": format!("Layer '{}' sospeso — gli altri layer e la hard-WAF restano attivi", l.as_str()),
    })))
}

/// POST /safe-mode/layer/{layer}/disable — riattiva UN solo layer.
async fn safe_mode_layer_disable_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(layer): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let Some(l) = ProtectionLayer::parse(&layer) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": "Unknown layer", "available_layers": ["edge", "neural", "behavioral"]
        })));
    };
    state.sentinel.resume_layer(l);
    (StatusCode::OK, Json(serde_json::json!({
        "layer": l.as_str(),
        "suspended": false,
        "suspended_layers": state.sentinel.suspended_layers(),
        "message": format!("Layer '{}' riattivato — blocking ripristinato", l.as_str()),
    })))
}

/// POST /safe-mode/enable — Enable safe mode (disable blocking, keep logging)
async fn safe_mode_enable_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    state.sentinel.enable_safe_mode();
    (StatusCode::OK, Json(serde_json::json!({
        "safe_mode_active": true,
        "suspended_layers": state.sentinel.suspended_layers(),
        "message": "Safe mode enabled (all layers) — blocking disabled except hard WAF patterns"
    })))
}

/// POST /safe-mode/disable — Disable safe mode (re-enable all blocking)
async fn safe_mode_disable_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }

    state.sentinel.disable_safe_mode();
    (StatusCode::OK, Json(serde_json::json!({
        "safe_mode_active": false,
        "suspended_layers": state.sentinel.suspended_layers(),
        "message": "Safe mode disabled (all layers) — full blocking re-enabled"
    })))
}

/// POST /honeypot/hit — Record a honeypot endpoint access and auto-ban repeat offenders
async fn honeypot_hit_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<HoneypotHitRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Forbidden" })),
        );
    }

    let ip: std::net::IpAddr = match payload.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid IP address" })),
            );
        }
    };

    // Record the honeypot hit
    let now = std::time::Instant::now();
    let event = HoneypotEvent {
        endpoint: payload.endpoint.clone(),
        user_agent: payload.user_agent.clone(),
        timestamp: now,
    };

    let hit_count = {
        let mut entry = HONEYPOT_TRACKER.entry(ip).or_default();
        // Prune old events outside the window
        entry.retain(|e| now.duration_since(e.timestamp) < HONEYPOT_WINDOW);
        entry.push(event);
        entry.len()
    };

    tracing::warn!(
        ip = %ip,
        endpoint = %payload.endpoint,
        user_agent = payload.user_agent.as_deref().unwrap_or("-"),
        hit_count = hit_count,
        "Honeypot hit recorded"
    );

    // LoRA structured channel — schema v1, JSONL, NO PM2 wrap.
    // Arricchimento geo: lookup via sentinel-edge ip_intel (country + ASN).
    let geo = state.sentinel.edge().ip_intel().lookup_country(ip);
    let asn_info = state.sentinel.edge().ip_intel().lookup_asn(ip);
    // 2026-06-04 audit gap closure: estrai JA3/JA4 PRIMA dell'emit per popolare
    // client.fingerprint nel JSONL events (consumer LoRA aveva sempre null).
    let ja3_hash_lc = payload
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-ja3-hash"))
        .map(|(_, v)| v.trim().to_lowercase());
    let ja4_lc = payload
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-ja4"))
        .map(|(_, v)| v.trim().to_string());
    // Correlation id: lega l'evento honeypot_hit all'eventuale ban_issued della
    // stessa invocazione → catena honeypot→ban tracciabile nel canale LoRA.
    let correlation_id = format!(
        "hp-{}-{}",
        ip,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let mut hp_event = LoraEvent::new(EventType::HoneypotHit, Severity::Warn, "sentinel-server")
        .with_client(&ip.to_string())
        .with_fingerprint(ja3_hash_lc.as_deref(), ja4_lc.as_deref())
        .with_correlation(&correlation_id);
    hp_event.client.country = geo;
    if let Some(asn) = asn_info.as_ref() {
        hp_event.client.asn = Some(asn.asn);
        hp_event.client.asn_org = Some(asn.org.clone());
        hp_event.client.is_datacenter = Some(asn.is_hosting);
    }
    hp_event.request = Some(RequestInfo {
        method: Some("GET".to_string()),
        path: Some(payload.endpoint.clone()),
        user_agent: payload.user_agent.clone(),
        ..Default::default()
    });
    hp_event.detection = Some(Detection {
        trigger_type: Some("honeypot_path".to_string()),
        trigger_value: Some(payload.endpoint.clone()),
        hit_count: Some(hit_count as u32),
        ..Default::default()
    });
    emit_event(hp_event);

    // JA3 instant-ban: se il TLS fingerprint match blocklist (curl-impersonate,
    // sqlmap, nikto, hydra, Burp, Acunetix, Selenium, ...) → ban IMMEDIATO
    // bypassando il threshold 3-hit. Scanner noti non meritano grace period.
    // ja3_hash_lc + ja4_lc estratti prima dell'emit dell'evento (vedi sopra).
    let ja3_instant_ban = ja3_hash_lc
        .as_deref()
        .and_then(sentinel_edge::ja3_blocklist::check_ja3);

    // JA4 instant-ban (2026-06-02): JA3 obsoleto per browser moderni (Chrome 90+
    // randomizza extension order → JA3 hash differente ogni request). JA4 normalizza
    // l'ordine → STABLE hash. Verifichiamo PRIMA il match JA4 full (più preciso),
    // POI il prefix automation (più generico).
    let ja4_instant_ban: Option<&'static str> = ja4_lc
        .as_deref()
        .and_then(sentinel_edge::tls_known_patterns::ja4_full_blocklist_match);

    // 2026-06-07: known-attack-path INSTANT-BAN — Layer 2.5 defense-in-depth.
    // Alcuni URI sono inequivocabilmente attacchi (PHPUnit RCE CVE-2017-9841,
    // PHP-CGI CVE-2012-1823, Log4Shell, Spring4Shell, webshell). Nessuna app
    // legit nostra (Hono/TS/Vite) ci finisce sopra. Match al PRIMO hit = ban.
    // Incident driver: scanner OVH 198.50.202.93 con 29 hit /vendor/phpunit/...
    // /eval-stdin.php senza ban (nginx HTTP→HTTPS 301 + libredtail-http che
    // non segue 3xx → portal/sentinel mai raggiunti).
    let known_attack_ban = sentinel_edge::known_attack_paths::check_known_attack_path(
        &payload.endpoint,
    );

    let force_ban = ja3_instant_ban.is_some()
        || ja4_instant_ban.is_some()
        || known_attack_ban.is_some()
        || hit_count >= HONEYPOT_BAN_THRESHOLD;

    if let Some(blocked) = &ja3_instant_ban {
        tracing::warn!(
            ip = %ip,
            ja3_hash = ja3_hash_lc.as_deref().unwrap_or("-"),
            ja3_label = %blocked.label,
            "JA3 INSTANT-BAN: TLS fingerprint matches known scanner/tool blocklist"
        );
    }
    if let Some(ja4_label) = ja4_instant_ban {
        tracing::warn!(
            ip = %ip,
            ja4 = ja4_lc.as_deref().unwrap_or("-"),
            ja4_label = %ja4_label,
            "JA4 INSTANT-BAN: TLS fingerprint (stable JA4) matches known scanner/tool blocklist"
        );
    }
    if let Some(attack) = &known_attack_ban {
        tracing::warn!(
            ip = %ip,
            attack_family = attack.family.as_str(),
            attack_label = %attack.label,
            endpoint = %payload.endpoint,
            "PATH INSTANT-BAN: known attack pattern (CVE / RCE / webshell)"
        );
    }

    // Auto-ban if threshold exceeded OR JA3 instant-ban — F5: escalation per recidivi
    let banned = if force_ban {
        let (duration, recidive_count) = compute_escalated_ban_duration(ip);
        // Fase ML (2026-07-07): variante con feature — la riga security_threats
        // del ban honeypot ora porta il vettore per il training (mig 098).
        let mlf = build_honeypot_ml_features(&state, ip, &payload);
        state.sentinel.response().ban_ip_with_features(
            ip,
            sentinel_response::BanReason::HoneypotTriggered,
            duration,
            mlf,
        ).await;

        // F7 (2026-06-02): persisti immediato in Postgres (fire-and-forget).
        // Senza questa chiamata, restart sentinel = perdita count → IP
        // cronico ritorna a recidive #1 → ban 7gg invece di 365gg.
        let now_epoch = epoch_now_secs();
        state.ledger_portal_client.send_offender_bump(
            sentinel_persistence::OffenderBumpPayload {
                ip_address: ip.to_string(),
                ban_count: recidive_count,
                last_banned_at_epoch_secs: now_epoch,
            },
        );

        // G13 wired (2026-06-02): broadcast bump cross-instance via Redis pub/sub.
        // Single-pod (no SENTINEL_LEDGER_SYNC_REDIS_URL) = no-op.
        // Multi-pod = altri pod ricevono e aggiornano HONEYPOT_OFFENDER_LEDGER locale.
        let sync = state.ledger_sync.clone();
        let ip_str = ip.to_string();
        tokio::spawn(async move {
            sync.publish_bump(&ip_str, recidive_count, now_epoch).await;
        });

        tracing::warn!(
            ip = %ip,
            hit_count = hit_count,
            ban_duration_secs = duration.as_secs(),
            recidive_count = recidive_count,
            "IP auto-banned for repeated honeypot hits (F5 escalation, F7 persisted)"
        );

        // G21.1 (2026-06-11): lo spike-breaker NON è più cablato qui.
        // I ban honeypot/known-attack/JA3 sono ad ALTA confidenza: il
        // notifier registrato su BanManager (register_ban_spike_breaker)
        // li classifica High → non alimentano il counter. Un flood di
        // scanner ora incontra PIÙ difesa, non spegne il blocking.

        // LoRA: ban event con geo + classifier (no ONNX score qui — solo
        // honeypot heuristic, classifier_score = None per questo trigger).
        let geo_ban = state.sentinel.edge().ip_intel().lookup_country(ip);
        let asn_ban = state.sentinel.edge().ip_intel().lookup_asn(ip);
        let mut ban_event = LoraEvent::new(EventType::BanIssued, Severity::High, "sentinel-server")
            .with_client(&ip.to_string())
            .with_fingerprint(ja3_hash_lc.as_deref(), ja4_lc.as_deref())
            .with_correlation(&correlation_id);
        ban_event.client.country = geo_ban;
        if let Some(asn) = asn_ban.as_ref() {
            ban_event.client.asn = Some(asn.asn);
            ban_event.client.asn_org = Some(asn.org.clone());
            ban_event.client.is_datacenter = Some(asn.is_hosting);
        }
        ban_event.detection = Some(Detection {
            trigger_type: Some("honeypot_path".to_string()),
            trigger_value: Some(payload.endpoint.clone()),
            hit_count: Some(hit_count as u32),
            ..Default::default()
        });
        ban_event.detection = Some(Detection {
            trigger_type: Some("honeypot_path".to_string()),
            trigger_value: Some(payload.endpoint.clone()),
            hit_count: Some(hit_count as u32),
            classifier_score: Some(0.99),
            matched_patterns: Some(vec![format!(
                "Honeypot endpoint colpito {} volte in 24h — recidive count: {}",
                hit_count, recidive_count,
            )]),
            ..Default::default()
        });
        ban_event.response_action = Some(ResponseAction {
            action_taken: Some("ban".to_string()),
            ban_duration_secs: Some(duration.as_secs()),
            ban_reason: Some(format!(
                "Honeypot endpoint triggered (recidive #{recidive_count})"
            )),
            escalation_level: Some(recidive_count as u8),
        });
        emit_event(ban_event);

        true
    } else {
        false
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "recorded": true,
            "ip": ip.to_string(),
            "hit_count": hit_count,
            "banned": banned,
            "threshold": HONEYPOT_BAN_THRESHOLD
        })),
    )
}

// ─── F9 (2026-06-02): atomic cursor write helper ────────────────────

/// Scrive `value` su `path` in modo atomico via tempfile + rename.
/// Crash-safe: il rename POSIX e\` atomico, quindi `path` o contiene
/// il valore precedente o il nuovo, mai uno stato parziale.
fn atomic_write_cursor(path: &std::path::Path, value: u64) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "cursor path has no parent directory",
    ))?;
    // Crea parent dir se manca (idempotente)
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = parent.join(format!(
        ".sentinel-lora-cursor.tmp.{}",
        std::process::id(),
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        writeln!(f, "{value}")?;
        f.sync_all()?; // fsync per garantire durabilita\` pre-rename
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ─── F4 (2026-06-02): Response observation + LoRA event drain ────────

/// Payload for POST /response/observed.
/// Portal/Runtime middleware POSTa qui DOPO aver renderato la risposta.
/// Permette al WAF di vedere status code lato origin (essenziale per
/// Rule 1: 4xx burst per IP).
#[derive(serde::Deserialize)]
struct ResponseObservedRequest {
    ip: String,
    status: u16,
    path: Option<String>,
}

/// POST /response/observed — alimenta Layer 3 Rule 1 (4xx burst).
/// Se l'IP supera la soglia 4xx, viene emesso un evento LoRA + (in futuro)
/// si potrà bannare via response.ban_ip. Per ora ritorna detection metadata.
async fn response_observed_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<ResponseObservedRequest>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let ip: std::net::IpAddr = match payload.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid IP address" })),
        ),
    };

    // Rule 1 (4xx burst): record nel layer3
    let detection = state.sentinel.behavior().record_response(ip, payload.status);

    // Se è scattato il signal forte (severity_score >= 0.85) → ban immediato.
    if let Some(d) = detection.as_ref() {
        if d.severity_score >= 0.85 {
            // G21.1: reason dedicato — behavioral = bassa confidenza, alimenta
            // lo spike-breaker via notifier (HoneypotTriggered lo bypassava).
            state.sentinel.response().ban_ip(
                ip,
                sentinel_response::BanReason::Behavioral4xxBurst,
                std::time::Duration::from_secs(7 * 24 * 60 * 60),
            ).await;

            // LoRA emit: ban event tied to detection
            let geo = state.sentinel.edge().ip_intel().lookup_country(ip);
            let asn = state.sentinel.edge().ip_intel().lookup_asn(ip);
            let mut ev = LoraEvent::new(EventType::BanIssued, Severity::High, "sentinel-server")
                .with_client(&ip.to_string());
            ev.client.country = geo;
            if let Some(a) = asn.as_ref() {
                ev.client.asn = Some(a.asn);
                ev.client.asn_org = Some(a.org.clone());
                ev.client.is_datacenter = Some(a.is_hosting);
            }
            ev.request = Some(RequestInfo {
                method: None,
                path: payload.path.clone(),
                user_agent: None,
                ..Default::default()
            });
            ev.detection = Some(Detection {
                trigger_type: Some(d.rule_id.to_string()),
                trigger_value: Some(format!("status:{}", payload.status)),
                hit_count: Some(d.evidence_count as u32),
                classifier_score: Some(d.severity_score as f32),
                matched_patterns: Some(vec![d.human_description.clone()]),
                ..Default::default()
            });
            ev.response_action = Some(ResponseAction {
                action_taken: Some("ban".to_string()),
                ban_duration_secs: Some(7 * 24 * 60 * 60),
                ban_reason: Some(d.decision_label.to_string()),
                escalation_level: Some(2),
            });
            emit_event(ev);

            tracing::warn!(
                ip = %ip,
                rule = %d.rule_id,
                count = d.evidence_count,
                score = d.severity_score,
                "Layer 3 behavioral rule fired — IP banned (4xx burst)"
            );
        }
    }

    // ── Slow-enumeration detector (2026-06-20) — SHADOW MODE ────────────────────
    // Ortogonale a honeypot (esca, 1-hit) e Rule-1 (volume): conta la VARIETÀ di path
    // DISTINTI in errore-di-probing (401/403/404) per IP in 15min → chi mappa la struttura
    // reale, lento e sotto-rate. NON banna: registra un threat-record `sentinel_enumeration`
    // con action="shadow" → compare in dashboard + report, per valutare nei prossimi giorni
    // se i candidate sarebbero ban giustificati. Cooldown per-IP nel detector (anti-spam).
    if let Some(path) = payload.path.as_deref() {
        if let Some(cand) = state.sentinel.behavior().record_enumeration(ip, payload.status, path) {
            state.ledger_portal_client.send_threat(ThreatPayload {
                r#type: "slow_enumeration".to_string(),
                severity: ThreatSeverity::Medium,
                ip_address: Some(ip.to_string()),
                request_id: None,
                confidence: 0.6,
                risk_score: 0.6,
                detection_source: "sentinel_enumeration".to_string(),
                description: format!(
                    "[SHADOW] L'IP ha sondato {} path distinti in errore-di-probing (401/403/404) \
                     in {} minuti — profilo di enumeration della struttura reale (sotto-rate, evita \
                     le esche honeypot). NON bannato: candidate per valutazione.",
                    cand.distinct_count,
                    cand.window_secs / 60,
                ),
                evidence: Some(serde_json::json!({
                    "distinct_paths": cand.distinct_count,
                    "window_secs": cand.window_secs,
                    "sample_paths": cand.sample_paths,
                    "mode": "shadow",
                })),
                raw_request: None,
                action_taken: Some("shadow".to_string()),
                action_details: None,
                // 2026-08-02: PRIMA era None, e la zona grigia restava fuori dal dataset —
                // proprio il traffico che l'honeypot non conosce, cioè l'unico capace di
                // insegnare qualcosa di nuovo al modello. Ora il vettore c'è, con i segnali
                // che questo punto di osservazione conosce davvero (path sondato, metodo,
                // ora) e `None` dichiarato su quelli che non attraversa (nessun layer
                // comportamentale né neurale sul /response).
                ml_features: build_enumeration_ml_features(ip, path, cand.distinct_count),
            });
            tracing::info!(
                ip = %ip,
                distinct = cand.distinct_count,
                "[SHADOW] slow-enumeration candidate registrato (NON bannato)"
            );
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "recorded": true,
        "detection": detection.map(|d| serde_json::json!({
            "rule_id": d.rule_id,
            "severity_score": d.severity_score,
            "evidence_count": d.evidence_count,
            "human_description": d.human_description,
            "decision_label": d.decision_label,
        })),
    })))
}

/// G19: GET /sla — top 20 tenant by request count
async fn sla_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let snapshot = state.sla_store.snapshot_top(20);
    (StatusCode::OK, Json(serde_json::json!({
        "tenant_count": state.sla_store.tenant_count(),
        "top": snapshot,
    })))
}

/// G19: GET /sla/top/{n} — top N tenant (max 100)
async fn sla_top_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(n): axum::extract::Path<usize>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let snapshot = state.sla_store.snapshot_top(n.min(100));
    (StatusCode::OK, Json(serde_json::json!({
        "tenant_count": state.sla_store.tenant_count(),
        "top": snapshot,
    })))
}

/// GET /events/since/{since_id} — drain Layer 3 events for LoRA pipeline.
/// Caller passa l'ultimo event_id processato; ritorna eventi più recenti.
async fn events_since_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(since_id): axum::extract::Path<u64>,
) -> impl IntoResponse {
    if !validate_internal_secret(&state, &headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "Forbidden" })));
    }
    let events = state.sentinel.behavior().drain_events_since(since_id);
    (StatusCode::OK, Json(serde_json::json!({
        "since_id": since_id,
        "count": events.len(),
        "events": events,
    })))
}

// ─────────────────────────────────────────────────────────────────────
// Tests — N3 audit (2026-05-29): verify validate_internal_secret behaviour.
// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use sentinel_core::SentinelConfig;

    fn make_state(secret: &str) -> AppState {
        let cfg = SentinelConfig::default();
        let sentinel = Arc::new(Sentinel::new(cfg).expect("sentinel init"));
        // Test: PortalClient no-op (no SENTINEL_INTERNAL_SECRET env set in unit-test env)
        let ledger_portal_client = PortalClient::spawn(PortalClientConfig::from_env());
        AppState {
            sentinel,
            expected_secret: secret.to_string(),
            ledger_portal_client,
            sla_store: std::sync::Arc::new(SlaStore::new()),
            ledger_sync: ledger_sync::LedgerSyncStore::disabled(),
        }
    }

    #[tokio::test]
    async fn validate_internal_secret_returns_false_when_header_missing() {
        let state = make_state("test-secret-32chars-pad-for-min-len");
        let headers = HeaderMap::new();
        assert!(!validate_internal_secret(&state, &headers));
    }

    #[tokio::test]
    async fn validate_internal_secret_returns_false_on_mismatch() {
        let state = make_state("expected-secret-with-padding-32ch");
        let mut headers = HeaderMap::new();
        headers.insert("x-sentinel-secret", "wrong-secret-but-same-len-padded!".parse().unwrap());
        assert!(!validate_internal_secret(&state, &headers));
    }

    #[tokio::test]
    async fn validate_internal_secret_returns_false_on_length_mismatch() {
        let state = make_state("expected-secret-with-padding-32ch");
        let mut headers = HeaderMap::new();
        headers.insert("x-sentinel-secret", "shorter".parse().unwrap());
        assert!(!validate_internal_secret(&state, &headers));
    }

    #[tokio::test]
    async fn validate_internal_secret_returns_true_on_exact_match() {
        let secret = "exact-secret-byte-by-byte-equal-32";
        let state = make_state(secret);
        let mut headers = HeaderMap::new();
        headers.insert("x-sentinel-secret", secret.parse().unwrap());
        assert!(validate_internal_secret(&state, &headers));
    }

    #[tokio::test]
    async fn validate_internal_secret_is_timing_safe_no_early_exit() {
        // Documenta che il match xor-accumulator NON ha early exit.
        // Senza un benchmark statistico non possiamo provare il timing-safe
        // ma il bytecode mostra: nessun `break` nel ciclo.
        // Vedi commento sul fix HIGH 2026-05-29.
        let secret = "timing-safe-secret-padded-to-32ch";
        let state = make_state(secret);
        let mut headers = HeaderMap::new();
        // Stessa lunghezza, differiscono SOLO sull'ultimo byte → non early exit
        let almost = "timing-safe-secret-padded-to-32cX";
        headers.insert("x-sentinel-secret", almost.parse().unwrap());
        assert!(!validate_internal_secret(&state, &headers));
    }

    // ── F5 (2026-06-02): repeat-offender escalation tests ────────────

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    fn ipv6_test(suffix: u16) -> std::net::IpAddr {
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0x2a06, 0x98c0, 0x3600, 0, 0, 0, 0, suffix,
        ))
    }

    #[test]
    fn escalation_first_ban_is_7_days() {
        // Cleanup any leftover from previous test runs (statics persist)
        let ip = ip4(192, 0, 2, 11);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        let (duration, count) = compute_escalated_ban_duration(ip);
        assert_eq!(count, 1, "first offence should be count=1");
        assert_eq!(duration, HONEYPOT_BAN_DURATION, "first ban = 7 days");
        assert_eq!(duration.as_secs(), 7 * 24 * 60 * 60);
    }

    #[test]
    fn escalation_second_ban_is_30_days() {
        let ip = ip4(192, 0, 2, 12);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        let _ = compute_escalated_ban_duration(ip);
        let (duration2, count2) = compute_escalated_ban_duration(ip);
        assert_eq!(count2, 2, "second offence should be count=2");
        assert_eq!(duration2, HONEYPOT_BAN_DURATION_2ND, "second ban = 30 days");
        assert_eq!(duration2.as_secs(), 30 * 24 * 60 * 60);
    }

    #[test]
    fn escalation_third_and_subsequent_bans_are_365_days() {
        let ip = ip4(192, 0, 2, 13);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        let _ = compute_escalated_ban_duration(ip);
        let _ = compute_escalated_ban_duration(ip);
        let (duration3, count3) = compute_escalated_ban_duration(ip);
        assert_eq!(count3, 3);
        assert_eq!(duration3, HONEYPOT_BAN_DURATION_3RD, "third ban = 365 days");
        assert_eq!(duration3.as_secs(), 365 * 24 * 60 * 60);

        // Fourth, fifth, etc → resta su 365 days (capped)
        let (duration4, count4) = compute_escalated_ban_duration(ip);
        assert_eq!(count4, 4);
        assert_eq!(duration4, HONEYPOT_BAN_DURATION_3RD, "fourth ban also 365 days (capped)");
    }

    #[test]
    fn escalation_ledger_persists_across_first_call() {
        let ip = ip4(192, 0, 2, 14);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        let _ = compute_escalated_ban_duration(ip);
        let entry = HONEYPOT_OFFENDER_LEDGER.get(&ip).expect("ledger entry should exist after first call");
        assert_eq!(entry.0, 1);
        assert!(entry.1 > 0, "timestamp should be epoch seconds > 0");
    }

    #[test]
    fn escalation_resets_after_90_day_silence() {
        let ip = ip4(192, 0, 2, 15);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        // Manually inject "ban happened 91 days ago, count was 3"
        let old_epoch = epoch_now_secs().saturating_sub(91 * 24 * 60 * 60);
        HONEYPOT_OFFENDER_LEDGER.insert(ip, (3, old_epoch));

        let (duration, count) = compute_escalated_ban_duration(ip);
        assert_eq!(count, 1, "ledger should reset after 90 days silence → count back to 1");
        assert_eq!(duration, HONEYPOT_BAN_DURATION, "back to first-ban duration");
    }

    #[test]
    fn escalation_does_not_reset_within_retention_window() {
        let ip = ip4(192, 0, 2, 16);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        // Ban happened 89 days ago — within retention → don't reset
        let recent_epoch = epoch_now_secs().saturating_sub(89 * 24 * 60 * 60);
        HONEYPOT_OFFENDER_LEDGER.insert(ip, (2, recent_epoch));

        let (duration, count) = compute_escalated_ban_duration(ip);
        assert_eq!(count, 3, "count should continue from 2 → 3 (no reset)");
        assert_eq!(duration, HONEYPOT_BAN_DURATION_3RD, "3rd ban duration = 365 days");
    }

    #[test]
    fn escalation_isolates_ips_independently() {
        let ip_a = ip4(192, 0, 2, 17);
        let ip_b = ip4(192, 0, 2, 18);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip_a);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip_b);

        let _ = compute_escalated_ban_duration(ip_a);
        let _ = compute_escalated_ban_duration(ip_a);
        let _ = compute_escalated_ban_duration(ip_a); // ip_a now at count=3

        let (duration_b, count_b) = compute_escalated_ban_duration(ip_b);
        assert_eq!(count_b, 1, "ip_b first offence, ip_a state should not leak");
        assert_eq!(duration_b, HONEYPOT_BAN_DURATION);
    }

    // ── F9 (2026-06-02): atomic cursor write tests ────────────────────

    #[test]
    fn f9_atomic_write_creates_file_with_value() {
        let tmp_dir = std::env::temp_dir().join(format!("sentinel-f9-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cursor = tmp_dir.join("cursor");

        atomic_write_cursor(&cursor, 12345).expect("write ok");
        let content = std::fs::read_to_string(&cursor).unwrap();
        assert_eq!(content.trim(), "12345");

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    #[test]
    fn f9_atomic_write_overwrites_existing_value() {
        let tmp_dir = std::env::temp_dir().join(format!("sentinel-f9-overwrite-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cursor = tmp_dir.join("cursor");

        atomic_write_cursor(&cursor, 100).unwrap();
        atomic_write_cursor(&cursor, 200).unwrap();
        atomic_write_cursor(&cursor, 999).unwrap();
        let content = std::fs::read_to_string(&cursor).unwrap();
        assert_eq!(content.trim(), "999");

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    #[test]
    fn f9_atomic_write_creates_parent_directory_if_missing() {
        let tmp_root = std::env::temp_dir().join(format!("sentinel-f9-deep-{}", std::process::id()));
        let nested_path = tmp_root.join("subdir-a").join("subdir-b").join("cursor");
        // Niente create_dir_all manuale — atomic_write_cursor lo fa

        atomic_write_cursor(&nested_path, 42).expect("creates parents");
        assert!(nested_path.exists());
        let content = std::fs::read_to_string(&nested_path).unwrap();
        assert_eq!(content.trim(), "42");

        std::fs::remove_dir_all(&tmp_root).ok();
    }

    #[test]
    fn f9_atomic_write_no_partial_file_left_on_disk() {
        let tmp_dir = std::env::temp_dir().join(format!("sentinel-f9-noresidue-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cursor = tmp_dir.join("cursor");

        atomic_write_cursor(&cursor, 7).unwrap();

        // Dopo write atomico, niente tempfile residuo nel parent
        let leftover_tmp_count = std::fs::read_dir(&tmp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".sentinel-lora-cursor.tmp"))
            .count();
        assert_eq!(leftover_tmp_count, 0, "tempfile DEVE essere stato rinominato, non lasciato");

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    #[test]
    fn f9_cursor_format_round_trip_u64() {
        let tmp_dir = std::env::temp_dir().join(format!("sentinel-f9-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cursor = tmp_dir.join("cursor");

        // Edge cases: 0, max u64, valori comuni
        for &val in &[0_u64, 1, 12345, u64::MAX] {
            atomic_write_cursor(&cursor, val).unwrap();
            let parsed: u64 = std::fs::read_to_string(&cursor)
                .unwrap()
                .trim()
                .parse()
                .expect("write -> read deve essere round-trip pulito");
            assert_eq!(parsed, val, "round-trip {val} fallito");
        }

        std::fs::remove_dir_all(&tmp_dir).ok();
    }

    // ── F6 (2026-06-02): LoRA-ready JSONL drain tests ─────────────────

    #[test]
    fn lora_event_for_layer3_detection_has_human_description() {
        // Verifica che un detection layer3 contenga il payload narrative
        // richiesto dalla pipeline LoRA (human_description + decision_label).
        let rules = sentinel_behavior::Layer3Rules::new();
        let ip = ip4(192, 0, 2, 50);
        // Trigger rule 1: 20 hit 4xx
        let mut last_detection = None;
        for _ in 0..20 {
            last_detection = rules.record_4xx(ip, 403);
        }
        let d = last_detection.expect("20 hit 403 → rule 1 deve scattare");
        assert!(!d.human_description.is_empty(), "human_description deve essere narrative");
        assert!(d.human_description.contains("4xx") || d.human_description.contains("scanner"),
                "narrative deve descrivere il pattern, got: {}", d.human_description);
        assert_eq!(d.decision_label, "ban_immediate");
        assert!(d.event_id > 0, "event_id deve essere monotonico > 0");
        assert!(d.detected_at_epoch_secs > 0, "timestamp deve essere epoch secs");
    }

    #[test]
    fn lora_event_jsonl_schema_serializes_clean() {
        // Verifica che RuleDetection serializzi a JSON valido (no #[serde(skip)])
        let rules = sentinel_behavior::Layer3Rules::new();
        let ip = ip4(192, 0, 2, 51);
        for _ in 0..20 { rules.record_4xx(ip, 404); }
        let d = rules.record_4xx(ip, 404).expect("rule triggered");
        let json = serde_json::to_string(&d).expect("serializzazione JSON ok");
        assert!(json.contains("event_id"));
        assert!(json.contains("rule_id"));
        assert!(json.contains("severity_score"));
        assert!(json.contains("human_description"));
        assert!(json.contains("decision_label"));
        assert!(json.contains("evidence_count"));
        // Single-line JSONL: no newlines embedded
        assert!(!json.contains('\n'), "JSONL = single line, no embedded newlines");
    }

    // ── F7 (2026-06-02): bootstrap_offender_ledger tests ─────────────

    #[tokio::test]
    async fn f7_bootstrap_offender_ledger_with_disabled_client_returns_ok() {
        // Client senza secret → fetch_offender_ledger ritorna Vec vuoto → bootstrap Ok
        let cfg = sentinel_persistence::PortalClientConfig {
            secret: String::new(),
            ..Default::default()
        };
        let client = sentinel_persistence::PortalClient::spawn(cfg);
        let result = bootstrap_offender_ledger(&client).await;
        assert!(result.is_ok(), "bootstrap con client disabilitato deve essere Ok");
    }

    #[tokio::test]
    async fn f7_bootstrap_populates_dashmap_from_fetch_results() {
        // Pre-popola DashMap con entry test, verifica che bootstrap NON le distrugga
        // (e\` un'add, non un truncate). Riempio il ledger manualmente come
        // farebbe il portal in caso di entry pre-esistente.
        let test_ip: std::net::IpAddr = "203.0.113.77".parse().unwrap();
        HONEYPOT_OFFENDER_LEDGER.insert(test_ip, (2, 1_780_000_000));
        let cfg = sentinel_persistence::PortalClientConfig {
            secret: String::new(),
            ..Default::default()
        };
        let client = sentinel_persistence::PortalClient::spawn(cfg);
        let result = bootstrap_offender_ledger(&client).await;
        assert!(result.is_ok());
        // Entry pre-esistente NON deve essere stata rimossa
        let entry = HONEYPOT_OFFENDER_LEDGER.get(&test_ip);
        assert!(entry.is_some(), "bootstrap NON deve truncare entry pre-esistenti");
        assert_eq!(entry.unwrap().0, 2);
        HONEYPOT_OFFENDER_LEDGER.remove(&test_ip);
    }

    #[tokio::test]
    async fn f7_bootstrap_idempotent_double_call() {
        // Doppia chiamata bootstrap NON deve duplicare entry / panic
        let cfg = sentinel_persistence::PortalClientConfig {
            secret: String::new(),
            ..Default::default()
        };
        let client = sentinel_persistence::PortalClient::spawn(cfg);
        bootstrap_offender_ledger(&client).await.expect("first call ok");
        bootstrap_offender_ledger(&client).await.expect("second call ok");
    }

    // ── G21.1 + G21.2 (2026-06-11): ban spike per-layer ──────────────
    // I test condividono gli static BAN_SPIKE_* → serializzati via lock
    // dedicato (cargo test parallelizza). Poison recovery con into_inner:
    // un assert fallito in un test non deve far risultare "poisoned" gli
    // altri mascherando il vero failure.
    static G21_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn g21_lock() -> parking_lot::MutexGuard<'static, ()> {
        G21_LOCK.lock()
    }

    fn g21_reset() {
        BAN_SPIKE_COUNTER.lock().clear();
        BAN_SPIKE_TRIGGERED_AT.lock().clear();
    }

    fn g21_layer_count(layer: ProtectionLayer) -> usize {
        BAN_SPIKE_COUNTER.lock().get(&layer).map(|q| q.len()).unwrap_or(0)
    }

    #[test]
    fn g21_threshold_constant_matches_requirement() {
        assert_eq!(BAN_SPIKE_THRESHOLD_PER_MIN, 100);
        assert_eq!(BAN_SPIKE_WINDOW.as_secs(), 60);
    }

    #[test]
    fn g21_layer_attribution_is_exhaustive_and_correct() {
        use sentinel_response::BanReason;
        // None = alta confidenza: nessun layer, nessun rollback. Se qualcuno
        // declassa honeypot a Some(layer), il flood di scanner torna a
        // spegnere la difesa (la regressione weaponizzabile).
        assert_eq!(ban_spike_layer(BanReason::HoneypotTriggered), None);
        assert_eq!(ban_spike_layer(BanReason::Manual), None);
        // Reason esplicite: 1:1 col layer che le produce.
        assert_eq!(ban_spike_layer(BanReason::RateLimitExceeded), Some(ProtectionLayer::Edge));
        assert_eq!(ban_spike_layer(BanReason::PromptInjection), Some(ProtectionLayer::Neural));
        assert_eq!(ban_spike_layer(BanReason::CriticalRisk), Some(ProtectionLayer::Neural));
        assert_eq!(ban_spike_layer(BanReason::Behavioral4xxBurst), Some(ProtectionLayer::Behavioral));
        assert_eq!(ban_spike_layer(BanReason::CoordinatedAttack), Some(ProtectionLayer::Behavioral));
        assert_eq!(ban_spike_layer(BanReason::ChallengeFailed), Some(ProtectionLayer::Behavioral));
    }

    #[test]
    fn g21_low_confidence_cascade_full_lifecycle_threshold_and_cooldown() {
        let _g = g21_lock();
        g21_reset();

        // 100 ban behavioral in 60s → trigger sul layer behavioral.
        // Phase 1: under threshold → no trigger
        for _ in 0..(BAN_SPIKE_THRESHOLD_PER_MIN - 1) {
            let (_, triggered) = record_ban_for_spike_check(ProtectionLayer::Behavioral);
            assert!(!triggered, "Phase 1: sotto soglia NON deve triggerare");
        }

        // Phase 2: hit + over threshold → 1 trigger, then no spam
        let mut trigger_count = 0;
        for _ in 0..15 {
            let (_, triggered) = record_ban_for_spike_check(ProtectionLayer::Behavioral);
            if triggered { trigger_count += 1; }
        }
        assert_eq!(trigger_count, 1, "Phase 2: DEVE triggerare esattamente una volta");

        // Phase 3: cooldown effective even after counter clear
        BAN_SPIKE_COUNTER.lock().clear();
        for _ in 0..(BAN_SPIKE_THRESHOLD_PER_MIN + 5) {
            let (_, triggered) = record_ban_for_spike_check(ProtectionLayer::Behavioral);
            assert!(!triggered, "Phase 3: cooldown 5min deve bloccare re-trigger");
        }
    }

    #[test]
    fn g21_counters_are_independent_per_layer() {
        let _g = g21_lock();
        g21_reset();

        // Requisito G21.2: i contatori NON si "diluiscono" tra loro. 99 ban
        // su Edge + 99 su Behavioral = nessuno dei due trigga (sotto soglia
        // CIASCUNO), anche se il totale è 198. Mutation check: se i contatori
        // fossero condivisi, il totale 198 ≥ 100 triggererebbe.
        for _ in 0..(BAN_SPIKE_THRESHOLD_PER_MIN - 1) {
            assert!(!record_ban_for_spike_check(ProtectionLayer::Edge).1);
            assert!(!record_ban_for_spike_check(ProtectionLayer::Behavioral).1);
        }
        assert_eq!(g21_layer_count(ProtectionLayer::Edge), BAN_SPIKE_THRESHOLD_PER_MIN - 1);
        assert_eq!(g21_layer_count(ProtectionLayer::Behavioral), BAN_SPIKE_THRESHOLD_PER_MIN - 1);
        assert_eq!(g21_layer_count(ProtectionLayer::Neural), 0, "Neural non ha visto ban");

        // Il 100° ban su Behavioral trigga SOLO behavioral; Edge resta a 99.
        let (count_b, trig_b) = record_ban_for_spike_check(ProtectionLayer::Behavioral);
        assert_eq!(count_b, BAN_SPIKE_THRESHOLD_PER_MIN);
        assert!(trig_b, "il 100° ban Behavioral DEVE triggerare");
        assert_eq!(g21_layer_count(ProtectionLayer::Edge), BAN_SPIKE_THRESHOLD_PER_MIN - 1,
            "Edge NON deve essere stato toccato dal trigger di Behavioral");
    }

    /// E2E granulare: attraversa il wiring REALE ban_ip → BanManager notifier
    /// → record_ban_for_spike_check → suspend_layer. Una riga coperta non è
    /// uno scope giusto: questo test fallisce se il notifier non viene
    /// registrato, se ban_ip non lo invoca, se l'attribuzione layer sbaglia,
    /// o se il safe-mode non è granulare.
    #[tokio::test]
    async fn g21_e2e_per_layer_isolation_honeypot_safe_behavioral_cascade_isolated() {
        let _g = g21_lock();
        g21_reset();

        let cfg = SentinelConfig::default();
        let sentinel = Arc::new(Sentinel::new(cfg).expect("sentinel init"));
        assert!(register_ban_spike_breaker(&sentinel), "primo register deve riuscire");
        assert!(!register_ban_spike_breaker(&sentinel), "set-once: secondo register deve fallire");
        assert!(!sentinel.is_safe_mode_active());

        // Phase A: 200 ban honeypot REALI (TEST-NET-3) → NESSUN layer sospeso.
        for i in 0..200u32 {
            let ip: std::net::IpAddr = format!("203.0.113.{}", i % 256).parse().unwrap();
            sentinel.response().ban_ip(
                ip, sentinel_response::BanReason::HoneypotTriggered,
                std::time::Duration::from_secs(60),
            ).await;
        }
        assert!(!sentinel.is_safe_mode_active(),
            "flood honeypot NON deve sospendere nessun layer (pre-fix lo faceva = weaponizzabile)");

        // Phase B: cascade behavioral (4xx-burst) → SOLO behavioral sospeso,
        // edge e neural restano ATTIVI. È il cuore di G21.2.
        g21_reset();
        for i in 0..BAN_SPIKE_THRESHOLD_PER_MIN {
            let ip: std::net::IpAddr = format!("198.51.100.{}", i % 256).parse().unwrap();
            sentinel.response().ban_ip(
                ip, sentinel_response::BanReason::Behavioral4xxBurst,
                std::time::Duration::from_secs(60),
            ).await;
        }
        assert!(sentinel.is_layer_suspended(ProtectionLayer::Behavioral),
            "cascade behavioral DEVE sospendere il layer behavioral");
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Edge),
            "edge NON deve essere sospeso da un cascade behavioral");
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Neural),
            "neural NON deve essere sospeso da un cascade behavioral");
        assert_eq!(sentinel.suspended_layers(), vec!["behavioral"]);

        // Phase C: cascade edge (rate-limit) mentre behavioral è già sospeso →
        // si aggiunge edge, neural resta su. Granularità additiva.
        for i in 0..BAN_SPIKE_THRESHOLD_PER_MIN {
            let ip: std::net::IpAddr = format!("198.51.100.{}", i % 256).parse().unwrap();
            sentinel.response().ban_ip(
                ip, sentinel_response::BanReason::RateLimitExceeded,
                std::time::Duration::from_secs(60),
            ).await;
        }
        assert!(sentinel.is_layer_suspended(ProtectionLayer::Edge), "cascade rate-limit → edge sospeso");
        assert!(sentinel.is_layer_suspended(ProtectionLayer::Behavioral), "behavioral resta sospeso");
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Neural), "neural resta ATTIVO");

        // Recupero granulare: riattiva behavioral, edge resta sospeso.
        sentinel.resume_layer(ProtectionLayer::Behavioral);
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Behavioral));
        assert!(sentinel.is_layer_suspended(ProtectionLayer::Edge));

        sentinel.disable_safe_mode();
        assert!(!sentinel.is_safe_mode_active());
        g21_reset();
    }

    #[test]
    fn escalation_real_case_ipv6_2a06_98c0_3600() {
        // Caso reale 2026-06-02: IP IPv6 2a06:98c0:3600::103 con ban scaduto 9gg fa,
        // 6538 hit oggi. Senza F5 il sistema lo ribloccava come prima volta (7gg).
        // Con F5 deve diventare recidive #2 → 30 giorni.
        let ip = ipv6_test(0x0103);
        HONEYPOT_OFFENDER_LEDGER.remove(&ip);

        // Simula ledger: first ban 16 giorni fa (9gg scaduto da quando ban di 7gg è expired)
        let first_ban_epoch = epoch_now_secs().saturating_sub(16 * 24 * 60 * 60);
        HONEYPOT_OFFENDER_LEDGER.insert(ip, (1, first_ban_epoch));

        let (duration, count) = compute_escalated_ban_duration(ip);
        assert_eq!(count, 2, "recidive within 90gg → count=2");
        assert_eq!(duration, HONEYPOT_BAN_DURATION_2ND);
        assert_eq!(duration.as_secs(), 30 * 24 * 60 * 60, "30 giorni ban");
    }
}
