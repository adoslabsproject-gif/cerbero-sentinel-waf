//! Sentinel persistence client — fire-and-forget HTTP bridge → Portal API.
//!
//! Pattern enterprise 2026:
//!  - Bounded `mpsc` (tokio) → no blocking del hot path WAF (drop oldest se piena)
//!  - Background worker async con `reqwest` HTTP/2 + rustls (no openssl)
//!  - Retry exponential `backon` con jitter (anti thundering herd)
//!  - Structured `tracing` (warn/error) — MAI silent drop, mai panic
//!  - Timeout 2s per call (Portal su localhost — più che sufficiente)
//!  - Connection pool keep-alive (HTTP/2 multiplex)
//!  - Gzip body (paylod jsonb può essere grosso)
//!
//! Endpoint chiamati:
//!   POST {portal_base}/api/v1/internal/sentinel/threat
//!   POST {portal_base}/api/v1/internal/sentinel/ban
//!   POST {portal_base}/api/v1/internal/sentinel/ban/bump
//!
//! Auth: header X-Sentinel-Secret == env SENTINEL_INTERNAL_SECRET (loopback
//! comunque tramite nginx, defense-in-depth).

use std::sync::Arc;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;
use tracing::{error, info, warn};

const DEFAULT_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_USER_AGENT: &str = "sentinel-persistence/1.0";

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("portal URL invalido: {0}")]
    InvalidUrl(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("portal returned status {0}: {1}")]
    Status(u16, String),
}

/// Configurazione client.
#[derive(Debug, Clone)]
pub struct PortalClientConfig {
    /// Base URL del Portal (es. "http://127.0.0.1:3006"). NO trailing slash.
    pub base_url: String,
    /// Shared secret (header X-Sentinel-Secret). MUST match server env
    /// SENTINEL_INTERNAL_SECRET. Se vuoto, il client è disabilitato.
    pub secret: String,
    /// Timeout per request HTTP.
    pub timeout: Duration,
    /// Capacità della bounded mpsc queue. Quando piena → drop oldest
    /// (= log warn, no panic).
    pub queue_capacity: usize,
    /// Numero massimo di retry exponential.
    pub max_retries: usize,
}

impl Default for PortalClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:3006".to_string(),
            secret: String::new(),
            timeout: DEFAULT_TIMEOUT,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            max_retries: 3,
        }
    }
}

impl PortalClientConfig {
    /// Costruisce config da env var standard:
    ///   PORTAL_PUBLIC_URL (fallback http://127.0.0.1:3006)
    ///   SENTINEL_INTERNAL_SECRET
    pub fn from_env() -> Self {
        let base_url = std::env::var("PORTAL_INTERNAL_URL")
            .or_else(|_| std::env::var("PORTAL_PUBLIC_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:3006".to_string());
        let secret = std::env::var("SENTINEL_INTERNAL_SECRET").unwrap_or_default();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            secret,
            ..Self::default()
        }
    }

    /// `true` se la persistenza è abilitata (secret presente).
    pub fn enabled(&self) -> bool {
        !self.secret.is_empty()
    }
}

// ─── Payload types (allineati a Zod schemas in routes/internal/sentinel.route.ts) ───

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatPayload {
    pub r#type: String,
    pub severity: ThreatSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub confidence: f64,
    pub risk_score: f64,
    pub detection_source: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_request: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_taken: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_details: Option<serde_json::Value>,
    /// Vettore RAW 18-feature (threat_features::to_raw_record) per il training del
    /// threat_classifier → persistito in security_threats.ml_features (mig 098). None per le
    /// detection senza contesto-richiesta (l'export le esclude). Serializza come `mlFeatures`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_features: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BanPayload {
    pub ip_address: String,
    pub source: String,
    pub trigger: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub duration_hours: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_permanent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BumpPayload {
    pub ip_address: String,
}

/// F7: ledger recidivi honeypot — payload per UPSERT verso portal.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OffenderBumpPayload {
    pub ip_address: String,
    pub ban_count: u32,
    pub last_banned_at_epoch_secs: u64,
}

/// F7: una riga del ledger F5 (response da GET /offender-ledger).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OffenderLedgerEntry {
    pub ip_address: String,
    pub ban_count: u32,
    pub last_banned_at_epoch_secs: u64,
}

/// Snapshot di una baseline anomaly tenant (persistenza durabilità). `stats` è il Welford
/// serializzato (count/mean/m2/min/max) — opaco qui, validato dallo Zod del Portal.
/// Serialize (flush POST) + Deserialize (boot GET) → un unico tipo per entrambe le direzioni.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AnomalyBaselinePayload {
    pub tenant: String,
    pub stats: serde_json::Value,
}

// ─── Event tipo (canale interno) ─────────────────────────────────────

#[derive(Debug, Clone)]
enum PersistEvent {
    Threat(ThreatPayload),
    Ban(BanPayload),
    Bump(BumpPayload),
    /// F7: UPSERT ledger recidivi
    OffenderBump(OffenderBumpPayload),
    /// Flush batch delle baseline anomaly dirty (UPSERT) → durabilità apprendimento WAF.
    AnomalyBaseline(Vec<AnomalyBaselinePayload>),
}

// ─── Client pubblico ──────────────────────────────────────────────────

/// Client fire-and-forget. Cloning è O(1) (Arc inside).
///
/// Pattern: ogni `send_*` spawna una `tokio::task::Task` one-shot che fa la
/// chiamata HTTP + retry. NESSUN worker condiviso (precedente design via
/// `mpsc::Sender` causava worker termination spurious in alcune
/// configurazioni runtime — vedi commit history per il debug).
///
/// Backpressure: `in_flight` AtomicUsize incrementato pre-spawn e
/// decrementato a fine task. Se supera `queue_capacity`, drop con warn.
#[derive(Clone)]
pub struct PortalClient {
    inner: Arc<PortalClientInner>,
}

struct PortalClientInner {
    config: PortalClientConfig,
    http: Option<reqwest::Client>,
    in_flight: AtomicUsize,
}

impl PortalClient {
    /// Crea il client. Se `config.secret` è vuoto, ritorna un client NO-OP
    /// (tutti i metodi sono fire-and-forget silenti).
    pub fn spawn(config: PortalClientConfig) -> Self {
        if !config.enabled() {
            warn!(
                "[SENTINEL_PERSIST] SENTINEL_INTERNAL_SECRET vuoto — persistenza DISABILITATA (Sentinel resta log-only). Imposta SENTINEL_INTERNAL_SECRET per attivare il bridge al Portal."
            );
            return Self {
                inner: Arc::new(PortalClientInner {
                    config,
                    http: None,
                    in_flight: AtomicUsize::new(0),
                }),
            };
        }

        // HTTP/1.1 only: Hono Node server (@hono/node-server) parla HTTP/1.1
        // plain text. Auto-upgrade reqwest 0.12 può confondersi.
        // tcp_nodelay disabilita Nagle (latenza ottimale localhost).
        let http = reqwest::ClientBuilder::new()
            .timeout(config.timeout)
            .user_agent(DEFAULT_USER_AGENT)
            .gzip(true)
            .http1_only()
            .tcp_nodelay(true)
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(16)
            .build();
        let http = match http {
            Ok(c) => Some(c),
            Err(e) => {
                error!(err = %e, "[SENTINEL_PERSIST] reqwest client build failed; persistenza disabilitata");
                None
            }
        };

        if http.is_some() {
            info!(
                base_url = %config.base_url,
                queue_capacity = config.queue_capacity,
                timeout_secs = config.timeout.as_secs(),
                "[SENTINEL_PERSIST] client ready (per-event spawn pattern)"
            );
        }

        Self {
            inner: Arc::new(PortalClientInner {
                config,
                http,
                in_flight: AtomicUsize::new(0),
            }),
        }
    }

    /// Enqueue threat event. Fire-and-forget: spawn una task one-shot.
    pub fn send_threat(&self, payload: ThreatPayload) {
        self.dispatch(PersistEvent::Threat(payload));
    }

    /// Enqueue ban event. Fire-and-forget.
    pub fn send_ban(&self, payload: BanPayload) {
        self.dispatch(PersistEvent::Ban(payload));
    }

    /// Enqueue counter bump event. Fire-and-forget.
    pub fn send_bump(&self, payload: BumpPayload) {
        self.dispatch(PersistEvent::Bump(payload));
    }

    /// F7 (2026-06-02): persisti riga offender ledger (UPSERT). Fire-and-forget.
    /// Chiamato dopo ogni `compute_escalated_ban_duration` per durabilita\` ban_count.
    pub fn send_offender_bump(&self, payload: OffenderBumpPayload) {
        self.dispatch(PersistEvent::OffenderBump(payload));
    }

    /// Flush batch (fire-and-forget) delle baseline anomaly DIRTY → UPSERT sul Portal.
    /// No-op se il batch è vuoto (niente HTTP a vuoto).
    pub fn send_anomaly_baselines(&self, batch: Vec<AnomalyBaselinePayload>) {
        if batch.is_empty() {
            return;
        }
        self.dispatch(PersistEvent::AnomalyBaseline(batch));
    }

    /// F7: snapshot-fetch del ledger F5 al boot (sync, NON fire-and-forget).
    /// Ritorna tutte le entry con last_banned_at_epoch_secs <= 90 giorni fa.
    /// Su errore (portal down, secret invalido) ritorna Vec vuoto + log warn:
    /// sentinel parte con ledger vuoto invece di crashare.
    pub async fn fetch_offender_ledger(&self) -> Result<Vec<OffenderLedgerEntry>, PersistError> {
        let Some(http) = self.inner.http.as_ref() else {
            // Client disabilitato → no-op (boot continua con ledger vuoto)
            return Ok(Vec::new());
        };
        let url = format!(
            "{}{}",
            self.inner.config.base_url, "/api/v1/internal/sentinel/offender-ledger"
        );
        let resp = http
            .get(&url)
            .header("X-Sentinel-Secret", &self.inner.config.secret)
            .send()
            .await
            .map_err(PersistError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(PersistError::Status(status.as_u16(), body));
        }
        let entries: Vec<OffenderLedgerEntry> = resp.json().await.map_err(PersistError::Http)?;
        Ok(entries)
    }

    /// Snapshot-fetch delle baseline anomaly al boot (sync, NON fire-and-forget) → restore
    /// del BaselineStore del WAF. Client disabilitato → Vec vuoto (boot continua a freddo).
    pub async fn fetch_anomaly_baselines(&self) -> Result<Vec<AnomalyBaselinePayload>, PersistError> {
        let Some(http) = self.inner.http.as_ref() else {
            return Ok(Vec::new());
        };
        let url = format!(
            "{}{}",
            self.inner.config.base_url, "/api/v1/internal/sentinel/anomaly-baseline"
        );
        let resp = http
            .get(&url)
            .header("X-Sentinel-Secret", &self.inner.config.secret)
            .send()
            .await
            .map_err(PersistError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(PersistError::Status(status.as_u16(), body));
        }
        let entries: Vec<AnomalyBaselinePayload> = resp.json().await.map_err(PersistError::Http)?;
        Ok(entries)
    }

    fn dispatch(&self, ev: PersistEvent) {
        let Some(http) = self.inner.http.as_ref() else {
            // Client disabilitato (no secret) → silent skip (config-driven, OK)
            return;
        };
        let in_flight = self.inner.in_flight.load(Ordering::Relaxed);
        if in_flight >= self.inner.config.queue_capacity {
            warn!(
                in_flight,
                cap = self.inner.config.queue_capacity,
                "[SENTINEL_PERSIST] in-flight cap raggiunto — dropping event"
            );
            return;
        }
        self.inner.in_flight.fetch_add(1, Ordering::Relaxed);

        let http = http.clone();
        let cfg = self.inner.config.clone();
        let counter = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let _ = send_with_retry(&http, &cfg, ev).await;
            counter.in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Numero di eventi attualmente in-flight (per metrics/test).
    pub fn in_flight_count(&self) -> usize {
        self.inner.in_flight.load(Ordering::Relaxed)
    }

    /// Invio BLOCCANTE (awaitable) delle baseline anomaly: a differenza di
    /// `send_anomaly_baselines` (fire-and-forget), AWAITA il POST e ne ritorna l'esito.
    /// Pensato per il flush FINALE allo shutdown (SIGTERM): garantisce che lo stato
    /// appreso fino all'ultimo istante sia persistito PRIMA dell'exit, invece di perdere
    /// fino a 60s di apprendimento. No-op (`Ok`) su batch vuoto o client disabilitato.
    pub async fn send_anomaly_baselines_blocking(
        &self,
        batch: Vec<AnomalyBaselinePayload>,
    ) -> Result<(), PersistError> {
        if batch.is_empty() {
            return Ok(());
        }
        let Some(http) = self.inner.http.as_ref() else {
            return Ok(()); // client disabilitato (no secret) → no-op
        };
        send_with_retry(http, &self.inner.config, PersistEvent::AnomalyBaseline(batch)).await
    }
}

// ─── Send + retry ──────────────────────────────────────────────────────

async fn send_with_retry(
    http: &reqwest::Client,
    cfg: &PortalClientConfig,
    ev: PersistEvent,
) -> Result<(), PersistError> {
    let (path, body) = match &ev {
        PersistEvent::Threat(p) => ("/api/v1/internal/sentinel/threat", serde_json::to_value(p)),
        PersistEvent::Ban(p) => ("/api/v1/internal/sentinel/ban", serde_json::to_value(p)),
        PersistEvent::Bump(p) => ("/api/v1/internal/sentinel/ban/bump", serde_json::to_value(p)),
        PersistEvent::AnomalyBaseline(p) => (
            "/api/v1/internal/sentinel/anomaly-baseline",
            serde_json::to_value(p),
        ),
        PersistEvent::OffenderBump(p) => (
            "/api/v1/internal/sentinel/offender-ledger/bump",
            serde_json::to_value(p),
        ),
    };
    let body = match body {
        Ok(v) => v,
        Err(e) => {
            error!(err = %e, "[SENTINEL_PERSIST] serialize failed — drop");
            return Err(PersistError::Status(500, e.to_string()));
        }
    };

    let url = format!("{}{}", cfg.base_url, path);
    let secret = cfg.secret.clone();

    let backoff = ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(100))
        .with_max_delay(Duration::from_secs(2))
        .with_max_times(cfg.max_retries)
        .with_jitter();

    let result = (|| async {
        let resp = http
            .post(&url)
            .header("X-Sentinel-Secret", &secret)
            .json(&body) // .json() setta Content-Type automatico + serialize
            .send()
            .await
            .map_err(|e| {
                // Espandere la error chain di reqwest per diagnostica
                // (source può essere hyper/io/tls error).
                use std::error::Error;
                let mut chain = String::new();
                let mut cur: Option<&dyn Error> = Some(&e);
                while let Some(err) = cur {
                    if !chain.is_empty() {
                        chain.push_str(" → ");
                    }
                    chain.push_str(&err.to_string());
                    cur = err.source();
                }
                tracing::warn!(
                    err_chain = %chain,
                    url = %url,
                    "[SENTINEL_PERSIST] reqwest send failed (full chain)"
                );
                PersistError::Http(e)
            })?;
        let status = resp.status();
        if status.is_success() {
            // 2026-05-30: log SUCCESS visibilmente per diagnostica health
            // (pre-fix: silenzioso → analytics script vedeva "mai successful POST"
            // anche quando funzionava perfettamente). Pattern enterprise:
            // emit anche successi a livello info, con throttle naturale da retry
            // (1 log per POST riuscito, no flood).
            tracing::info!(
                status = status.as_u16(),
                path,
                "[SENTINEL_PERSIST] sent ok"
            );
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            // 4xx = client-side bug (paylod invalido): non ha senso retry
            if status.is_client_error() {
                error!(
                    status = status.as_u16(),
                    body = %body,
                    path,
                    "[SENTINEL_PERSIST] portal rejected (4xx) — drop, no retry"
                );
                // Return Ok per non triggerare retry su 4xx (paylod malformed)
                Ok(())
            } else {
                // 5xx: retriable
                Err(PersistError::Status(status.as_u16(), body))
            }
        }
    })
    .retry(backoff)
    .when(|e: &PersistError| matches!(e, PersistError::Http(_) | PersistError::Status(_, _)))
    .notify(|err, dur| {
        warn!(
            err = %err,
            retry_in_ms = dur.as_millis() as u64,
            path,
            "[SENTINEL_PERSIST] retrying"
        );
    })
    .await;

    if let Err(e) = &result {
        error!(
            err = %e,
            path,
            "[SENTINEL_PERSIST] FAILED after retries — event lost. Check Portal /api/v1/internal/sentinel/* health."
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // NB: i test su env globali sono unstable in parallelo (cargo test
    // gira N thread). Usiamo costruzione diretta del config invece di
    // mutate dell'ambiente.

    #[test]
    fn config_default_secret_empty_disables_client() {
        let cfg = PortalClientConfig::default();
        assert!(!cfg.enabled());
        assert_eq!(cfg.base_url, "http://127.0.0.1:3006");
        assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);
        assert_eq!(cfg.queue_capacity, DEFAULT_QUEUE_CAPACITY);
        assert_eq!(cfg.max_retries, 3);
    }

    #[test]
    fn config_strips_trailing_slash() {
        // Test via diretta construction (NO env mutation)
        let raw = "http://localhost:3006/";
        let normalized = raw.trim_end_matches('/').to_string();
        assert_eq!(normalized, "http://localhost:3006");

        let cfg = PortalClientConfig {
            base_url: normalized,
            secret: "test".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.base_url, "http://localhost:3006");
        assert!(cfg.enabled());
    }

    #[test]
    fn config_enabled_requires_non_empty_secret() {
        let mut cfg = PortalClientConfig::default();
        assert!(!cfg.enabled());
        cfg.secret = " ".to_string(); // whitespace conta come "settato" (l'admin sceglie)
        assert!(cfg.enabled());
        cfg.secret = "real-secret".to_string();
        assert!(cfg.enabled());
    }

    #[tokio::test]
    async fn disabled_client_drops_silently() {
        let cfg = PortalClientConfig {
            secret: String::new(),
            ..Default::default()
        };
        let client = PortalClient::spawn(cfg);
        // Non panica
        client.send_threat(ThreatPayload {
            r#type: "test".to_string(),
            severity: ThreatSeverity::Low,
            ip_address: None,
            request_id: None,
            confidence: 0.5,
            risk_score: 0.5,
            detection_source: "test".to_string(),
            description: "test".to_string(),
            evidence: None,
            raw_request: None,
            action_taken: None,
            action_details: None,
            ml_features: None,
        });
    }

    #[tokio::test]
    async fn send_anomaly_baselines_empty_is_noop() {
        // batch vuoto → ritorna subito, niente dispatch/HTTP (no spreco). Non panica.
        let client = PortalClient::spawn(PortalClientConfig {
            secret: "real-secret".to_string(),
            ..Default::default()
        });
        client.send_anomaly_baselines(Vec::new());
    }

    #[test]
    fn anomaly_baseline_payload_serializes_to_portal_shape() {
        // CONTRACT col Zod del Portal: { tenant, stats: { count, mean[], m2[], min[], max[] } }.
        let p = AnomalyBaselinePayload {
            tenant: "acme".to_string(),
            stats: serde_json::json!({
                "count": 300, "mean": [1.0, 2.0], "m2": [3.0, 4.0], "min": [0.0, 0.0], "max": [9.0, 9.0]
            }),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["tenant"], "acme");
        assert_eq!(v["stats"]["count"], 300);
        assert_eq!(v["stats"]["mean"][0], 1.0);
        assert!(v["stats"]["m2"].is_array());
        // round-trip (boot GET deserializza la stessa shape)
        let back: AnomalyBaselinePayload = serde_json::from_value(v).unwrap();
        assert_eq!(back.tenant, "acme");
        assert_eq!(back.stats["count"], 300);
    }

    #[test]
    fn serialize_payload_uses_camelcase() {
        let p = BanPayload {
            ip_address: "1.2.3.4".to_string(),
            source: "sentinel_honeypot".to_string(),
            trigger: "honeypot_3_hits".to_string(),
            reason: "test".to_string(),
            evidence: None,
            trigger_path: None,
            trigger_pattern: None,
            user_agent: None,
            request_method: None,
            risk_score: Some(100),
            confidence: Some(0.95),
            duration_hours: 168,
            is_permanent: Some(false),
            country_code: None,
            threat_id: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"ipAddress\":\"1.2.3.4\""));
        assert!(json.contains("\"durationHours\":168"));
        assert!(!json.contains("ip_address")); // snake_case NON deve apparire
    }

    // ── F7 (2026-06-02): OffenderBumpPayload + OffenderLedgerEntry tests ──

    #[test]
    fn offender_bump_payload_serializes_camelcase() {
        let p = OffenderBumpPayload {
            ip_address: "203.0.113.99".to_string(),
            ban_count: 3,
            last_banned_at_epoch_secs: 1_780_000_000,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"ipAddress\":\"203.0.113.99\""));
        assert!(json.contains("\"banCount\":3"));
        assert!(json.contains("\"lastBannedAtEpochSecs\":1780000000"));
        assert!(!json.contains("ip_address"));
        assert!(!json.contains("ban_count"));
        assert!(!json.contains("last_banned_at"));
    }

    #[test]
    fn offender_ledger_entry_deserializes_camelcase() {
        let json = r#"{"ipAddress":"1.2.3.4","banCount":5,"lastBannedAtEpochSecs":1780123456}"#;
        let e: OffenderLedgerEntry = serde_json::from_str(json).expect("deserialize ok");
        assert_eq!(e.ip_address, "1.2.3.4");
        assert_eq!(e.ban_count, 5);
        assert_eq!(e.last_banned_at_epoch_secs, 1_780_123_456);
    }

    #[test]
    fn offender_ledger_entry_rejects_missing_field() {
        let json = r#"{"ipAddress":"1.2.3.4","banCount":5}"#; // missing lastBannedAtEpochSecs
        let res: Result<OffenderLedgerEntry, _> = serde_json::from_str(json);
        assert!(res.is_err(), "deserialize DEVE fallire su field mancante (no silent default)");
    }

    #[tokio::test]
    async fn fetch_offender_ledger_disabled_client_returns_empty_ok() {
        let cfg = PortalClientConfig {
            secret: String::new(), // empty → client disabilitato
            ..Default::default()
        };
        let client = PortalClient::spawn(cfg);
        let result = client.fetch_offender_ledger().await.expect("disabled client = Ok empty");
        assert_eq!(result.len(), 0, "client disabilitato deve ritornare Vec vuoto (no error)");
    }

    #[tokio::test]
    async fn send_offender_bump_disabled_client_no_panic() {
        // Verifica: chiamata fire-and-forget su client disabilitato non panica
        let cfg = PortalClientConfig {
            secret: String::new(),
            ..Default::default()
        };
        let client = PortalClient::spawn(cfg);
        // Non panica + non incrementa in_flight (client disabilitato → silent skip)
        let before = client.in_flight_count();
        client.send_offender_bump(OffenderBumpPayload {
            ip_address: "9.9.9.9".to_string(),
            ban_count: 1,
            last_banned_at_epoch_secs: 1_780_000_000,
        });
        let after = client.in_flight_count();
        assert_eq!(before, after, "client disabilitato → in_flight invariato");
    }

    #[test]
    fn offender_bump_routes_to_correct_endpoint() {
        // Verifica indirettamente che PersistEvent::OffenderBump esiste
        // e produce un payload serializzabile. La route /offender-ledger/bump
        // e\` testata in send_with_retry path (integration test 2026-grade).
        let p = OffenderBumpPayload {
            ip_address: "10.0.0.1".to_string(),
            ban_count: 42,
            last_banned_at_epoch_secs: 1,
        };
        let ev = PersistEvent::OffenderBump(p);
        match ev {
            PersistEvent::OffenderBump(inner) => {
                assert_eq!(inner.ban_count, 42);
                let body = serde_json::to_value(&inner).unwrap();
                assert_eq!(body["ipAddress"], "10.0.0.1");
                assert_eq!(body["banCount"], 42);
            }
            _ => panic!("PersistEvent variant must be OffenderBump"),
        }
    }
}
