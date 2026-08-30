/*!
LoRA-ready structured event channel — dataset training Liara integration future.

OUTPUT: `/opt/zeliai/shared/logs/sentinel-events-YYYY-MM-DD.jsonl`
Format: single-line JSON per event (NDJSON), nessun PM2 envelope.

Schema event (versione v1):
```json
{
  "schema_version": "v1",
  "event_id": "<uuid-v7 sortable by time>",
  "correlation_id": "<request-id or honeypot-trace>",
  "timestamp_iso": "2026-05-31T05:48:39.063Z",
  "timestamp_unix_ms": 1780203519063,
  "event_type": "honeypot_hit|ban_issued|threat_classified|persist_ok|persist_fail|escalation|whitelist",
  "severity": "INFO|WARN|HIGH|CRITICAL",
  "source": "sentinel-edge|sentinel-neural|sentinel-response|sentinel-persistence",

  "request": {
    "method": "GET|POST|...",
    "path": "/wp-admin/install.php",
    "user_agent": "Mozilla/5.0 ...",
    "referer": null,
    "status_returned": 403,
    "body_size": 0,
    "duration_ms": 12
  },

  "client": {
    "ip_hash": "<sha256(ip + salt) truncated 16 hex chars>",
    "ip_cleartext": "1.2.3.4",     // SOLO per audit, NON usato in LoRA training
    "country": "US",
    "asn": 16509,
    "asn_org": "Amazon.com, Inc.",
    "is_datacenter": true,
    "is_proxy": false,
    "is_tor": false,
    "fingerprint": "<browser+os hash>"
  },

  "detection": {
    "trigger_type": "honeypot_path|toxicity_classifier|rate_limit|geo_block|prompt_injection",
    "trigger_value": "/wp-admin",
    "hit_count": 1,
    "classifier_score": 0.92,       // ONNX threat_classifier output [0,1]
    "classifier_model": "toxicity.onnx",
    "matched_patterns": ["env_leak", "vcs_leak"]
  },

  "response_action": {
    "action_taken": "ban|monitor|drop|allow|escalate",
    "ban_duration_secs": 604800,
    "ban_reason": "Honeypot endpoint triggered",
    "escalation_level": 1
  },

  "context_for_llm": {
    // Campo dedicato per training Liara: prompt + completion-like
    // pre-strutturati per fine-tuning supervisionato.
    "summary": "datacenter IP scanned /wp-admin honeypot, classifier 0.92, banned 7d",
    "intent_label": "wordpress_scanner",
    "confidence": 0.95
  }
}
```

USO da codice Sentinel:
```rust
use crate::lora_log::{emit_event, LoraEvent, EventType, Severity};
emit_event(LoraEvent::honeypot_hit(ip, &path, &ua, hit_count, geo_info));
```

Pipeline rotation: nuovo file per giorno (Europe/Rome TZ).
*/

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use parking_lot::Mutex;
use std::time::SystemTime;
use uuid::Uuid;

const LOG_DIR: &str = "/opt/zeliai/shared/logs";
const SCHEMA_VERSION: &str = "v1";
// Salt fisso per ip_hash — NON è secret cryptografico, serve solo a impedire
// dictionary attack inverse (IP → hash) per pseudonomizzazione GDPR art.4(5).
// Cambiare il salt RUOTA tutti gli hash → break joinability storica.
const IP_HASH_SALT: &str = "zeliai-sentinel-lora-v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    HoneypotHit,
    BanIssued,
    ThreatClassified,
    PersistOk,
    PersistFail,
    Escalation,
    Whitelist,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Warn,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestInfo {
    pub method: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub status_returned: Option<u16>,
    pub body_size: Option<usize>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientInfo {
    pub ip_hash: String,
    pub ip_cleartext: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub is_datacenter: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_tor: Option<bool>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Detection {
    pub trigger_type: Option<String>,
    pub trigger_value: Option<String>,
    pub hit_count: Option<u32>,
    pub classifier_score: Option<f32>,
    pub classifier_model: Option<String>,
    pub matched_patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAction {
    pub action_taken: Option<String>,
    pub ban_duration_secs: Option<u64>,
    pub ban_reason: Option<String>,
    pub escalation_level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextForLlm {
    pub summary: Option<String>,
    pub intent_label: Option<String>,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraEvent {
    pub schema_version: String,
    pub event_id: String,
    pub correlation_id: Option<String>,
    pub timestamp_iso: String,
    pub timestamp_unix_ms: u64,
    pub event_type: EventType,
    pub severity: Severity,
    pub source: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestInfo>,
    pub client: ClientInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<Detection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_action: Option<ResponseAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_for_llm: Option<ContextForLlm>,
}

impl LoraEvent {
    pub fn new(event_type: EventType, severity: Severity, source: &str) -> Self {
        let now: DateTime<Utc> = SystemTime::now().into();
        let unix_ms = now.timestamp_millis() as u64;
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            event_id: Uuid::now_v7().to_string(),
            correlation_id: None,
            timestamp_iso: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            timestamp_unix_ms: unix_ms,
            event_type,
            severity,
            source: source.to_string(),
            request: None,
            client: ClientInfo::default(),
            detection: None,
            response_action: None,
            context_for_llm: None,
        }
    }

    pub fn with_client(mut self, ip: &str) -> Self {
        self.client.ip_hash = hash_ip(ip);
        self.client.ip_cleartext = Some(ip.to_string());
        self
    }

    /// 2026-06-04 audit gap closure: popola `client.fingerprint` nei JSONL
    /// events con JA3/JA4 hash (format `ja3=<hash>;ja4=<hash>`). Senza
    /// questo, il consumer LoRA non vede mai il TLS fingerprint nel dataset
    /// — anche se Sentinel lo riceve via header X-JA3-Hash/X-JA4 e lo usa
    /// per JA3/JA4 instant-ban.
    ///
    /// Skip se entrambi vuoti — evita rumore "ja3=;ja4=" su request senza
    /// nginx-ssl-fingerprint module (es. test interni o Cloudflare bypass).
    pub fn with_fingerprint(mut self, ja3_hash: Option<&str>, ja4: Option<&str>) -> Self {
        let ja3 = ja3_hash.unwrap_or("").trim();
        let ja4_v = ja4.unwrap_or("").trim();
        if ja3.is_empty() && ja4_v.is_empty() {
            return self;
        }
        let mut parts: Vec<String> = Vec::with_capacity(2);
        if !ja3.is_empty() {
            parts.push(format!("ja3={ja3}"));
        }
        if !ja4_v.is_empty() {
            parts.push(format!("ja4={ja4_v}"));
        }
        self.client.fingerprint = Some(parts.join(";"));
        self
    }

    /// Builder API per `correlation_id` (schema LoRA: lega eventi della stessa
    /// catena, es. honeypot_hit → ban_issued, per il training/analisi).
    pub fn with_correlation(mut self, id: &str) -> Self {
        self.correlation_id = Some(id.to_string());
        self
    }
}

/// SHA-256(salt || ip) truncated a 16 char hex — pseudonomizzazione GDPR-safe.
/// 64 bit di entropy sufficienti per joinability cross-event dello stesso IP
/// senza permettere dictionary inverse trivially (servirebbero 2^64 hash precomputati).
pub fn hash_ip(ip: &str) -> String {
    let mut h = Sha256::new();
    h.update(IP_HASH_SALT.as_bytes());
    h.update(ip.as_bytes());
    let result = h.finalize();
    // SAFE-SLICE: `result` è un digest Sha256 ([u8;32]), byte-array NON &str → nessun
    // problema di char-boundary; sempre ≥ 8 byte.
    hex_encode_short(&result[..8])
}

fn hex_encode_short(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// File handle daily rotation. Re-apre il file ogni emit perché tracing-style
/// roller è overkill per ~1k event/min. Costo: open syscall + append per event.
fn log_path() -> PathBuf {
    let now: DateTime<Utc> = SystemTime::now().into();
    let date = now.format("%Y-%m-%d");
    PathBuf::from(format!("{}/sentinel-events-{}.jsonl", LOG_DIR, date))
}

static EMIT_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

/// Emit event in sentinel-events-YYYY-MM-DD.jsonl con append atomico (mutex).
///
/// Fail-soft: errore I/O → log a tracing::warn ma NON propaga (non blocca request).
pub fn emit_event(event: LoraEvent) {
    let serialized = match serde_json::to_string(&event) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "[LORA_LOG] serialize fail");
            return;
        }
    };

    let path = log_path();
    let lock = EMIT_MUTEX.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock(); // parking_lot: nessun poisoning, guard diretto

    // G14 fix (2026-06-02): fsync (sync_all) DOPO write + PRIMA del return.
    // Senza, write_all va in buffer del kernel ma crash mid-flush perde evento
    // mentre il F9 cursor avrebbe registrato il successo → at-most-once invece
    // di at-least-once. Cost: ~0.1-1ms per fsync su SSD, accettabile per
    // garanzia durabilita\` LoRA pipeline.
    let result = OpenOptions::new()
        .create(true)
        .append(true)
        .mode_unix_chmod()
        .open(&path)
        .and_then(|mut f| {
            f.write_all(serialized.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()?; // G14: durabilita\` garantita prima di considerare done
            Ok(())
        });

    if let Err(e) = result {
        tracing::warn!(error = %e, path = %path.display(), "[LORA_LOG] write fail");
    }
}

// Helper trait per chmod 0640 cross-platform — su non-Unix è no-op.
trait OpenOptionsModeExt {
    fn mode_unix_chmod(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl OpenOptionsModeExt for OpenOptions {
    fn mode_unix_chmod(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o640)
    }
}

#[cfg(not(unix))]
impl OpenOptionsModeExt for OpenOptions {
    fn mode_unix_chmod(&mut self) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_schema_version() {
        let ev = LoraEvent::new(EventType::HoneypotHit, Severity::Warn, "sentinel-edge")
            .with_client("1.2.3.4");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"schema_version\":\"v1\""));
        assert!(json.contains("\"event_type\":\"honeypot_hit\""));
        assert!(json.contains("\"severity\":\"WARN\""));
        assert!(json.contains("\"ip_hash\":"));
        assert!(json.contains("\"ip_cleartext\":\"1.2.3.4\""));
    }

    #[test]
    fn ip_hash_deterministic() {
        assert_eq!(hash_ip("192.168.1.1"), hash_ip("192.168.1.1"));
        assert_ne!(hash_ip("192.168.1.1"), hash_ip("192.168.1.2"));
        // 16 char hex = 8 byte
        assert_eq!(hash_ip("1.2.3.4").len(), 16);
    }

    #[test]
    fn ip_hash_uses_salt() {
        // Hash != raw sha256 senza salt → conferma salting attivo
        let raw_sha = {
            let mut h = Sha256::new();
            h.update(b"1.2.3.4");
            // SAFE-SLICE: digest Sha256 ([u8;32]), byte-array non &str → no char-boundary.
            hex_encode_short(&h.finalize()[..8])
        };
        assert_ne!(hash_ip("1.2.3.4"), raw_sha);
    }

    #[test]
    fn event_uuid_v7_sortable_by_time() {
        let e1 = LoraEvent::new(EventType::HoneypotHit, Severity::Info, "test");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let e2 = LoraEvent::new(EventType::HoneypotHit, Severity::Info, "test");
        // UUIDv7 timestamp prefix → lessicograficamente ordinato
        assert!(e2.event_id > e1.event_id, "UUIDv7 should be time-sortable: {} vs {}", e1.event_id, e2.event_id);
    }

    #[test]
    fn event_with_full_chain() {
        let mut ev = LoraEvent::new(EventType::ThreatClassified, Severity::High, "sentinel-neural")
            .with_client("172.16.0.1")
            .with_correlation("req-abc-123");
        ev.detection = Some(Detection {
            trigger_type: Some("toxicity_classifier".to_string()),
            classifier_score: Some(0.87),
            classifier_model: Some("toxicity.onnx".to_string()),
            ..Default::default()
        });
        ev.response_action = Some(ResponseAction {
            action_taken: Some("monitor".to_string()),
            ..Default::default()
        });
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"classifier_score\":0.87"));
        assert!(json.contains("\"correlation_id\":\"req-abc-123\""));
        assert!(json.contains("\"action_taken\":\"monitor\""));
    }
}
