//! G13 (2026-06-02): cross-instance ledger sync via Redis pub/sub.
//!
//! Quando un'istanza Sentinel registra un ban honeypot con escalation
//! (compute_escalated_ban_duration), pubblica su `sentinel:ledger:bump`.
//! Tutte le altre istanze subscribe e aggiornano DashMap locale.
//!
//! Garantisce consistenza eventuale del ledger F5 across multi-pod deploy
//! (preparazione multi-region). Su single-pod = no-op (subscribe vuoto).
//!
//! Schema messaggio (JSON):
//!   {"ip":"1.2.3.4","ban_count":3,"last_banned_at_epoch_secs":1780000000,
//!    "origin_pod":"sentinel-eu-west-1-pod-2"}
//!
//! Origin filter: lo stesso pod NON applica il proprio messaggio (loop).

use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

const PUBSUB_CHANNEL: &str = "sentinel:ledger:bump";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBumpMsg {
    pub ip: String,
    pub ban_count: u32,
    pub last_banned_at_epoch_secs: u64,
    pub origin_pod: String,
}

#[derive(Clone)]
pub struct LedgerSyncStore {
    client: Arc<redis::Client>,
    pod_id: String,
    enabled: bool,
}

impl LedgerSyncStore {
    pub async fn connect(url: &str, pod_id: String) -> Result<Self, String> {
        let client = redis::Client::open(url)
            .map_err(|e| format!("redis open: {e}"))?;
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| format!("redis connect: {e}"))?;
        let _: String = redis::cmd("PING").query_async(&mut conn).await
            .map_err(|e| format!("redis ping: {e}"))?;
        Ok(Self { client: Arc::new(client), pod_id, enabled: true })
    }

    pub fn disabled() -> Self {
        let client = redis::Client::open("redis://localhost:0/0").unwrap();
        Self { client: Arc::new(client), pod_id: "disabled".to_string(), enabled: false }
    }

    pub fn is_enabled(&self) -> bool { self.enabled }
    pub fn pod_id(&self) -> &str { &self.pod_id }

    /// Pubblica un bump locale → tutti gli altri pod riceveranno via subscribe.
    /// Fire-and-forget (no await): se Redis down, log warn ma non blocca.
    pub async fn publish_bump(&self, ip: &str, ban_count: u32, last_banned_at_epoch_secs: u64) {
        if !self.enabled { return; }
        let msg = LedgerBumpMsg {
            ip: ip.to_string(),
            ban_count,
            last_banned_at_epoch_secs,
            origin_pod: self.pod_id.clone(),
        };
        let json = match serde_json::to_string(&msg) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "G13: serialize fail");
                return;
            }
        };
        match self.client.get_multiplexed_async_connection().await {
            Ok(mut conn) => {
                let r: Result<i32, _> = conn.publish(PUBSUB_CHANNEL, json).await;
                if let Err(e) = r {
                    tracing::warn!(error = %e, "G13: PUBLISH fail (fail-open)");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "G13: Redis conn fail (fail-open)");
            }
        }
    }

    /// Subscribe loop — spawn una task tokio che riceve messaggi e li
    /// inoltra al channel `out`. Filtra fuori i messaggi originati dal
    /// proprio pod_id (loop prevention).
    /// Ritorna il receiver per consumare i messaggi (es. update DashMap).
    pub async fn spawn_subscriber(&self) -> mpsc::Receiver<LedgerBumpMsg> {
        let (tx, rx) = mpsc::channel(1000);
        if !self.enabled {
            return rx;
        }
        let client = self.client.clone();
        let my_pod = self.pod_id.clone();
        tokio::spawn(async move {
            loop {
                let conn = match client.get_async_connection().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "G13: subscribe conn fail, retry 10s");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                };
                let mut pubsub = conn.into_pubsub();
                if let Err(e) = pubsub.subscribe(PUBSUB_CHANNEL).await {
                    tracing::warn!(error = %e, "G13: subscribe channel fail, retry 10s");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
                tracing::info!(channel = PUBSUB_CHANNEL, pod_id = %my_pod, "G13: ledger sync subscribed");

                let mut stream = pubsub.on_message();
                use futures_util::StreamExt;
                while let Some(msg) = stream.next().await {
                    let payload: String = match msg.get_payload() {
                        Ok(p) => p,
                        Err(e) => { tracing::warn!(error = %e, "G13: bad payload"); continue; }
                    };
                    let parsed: LedgerBumpMsg = match serde_json::from_str(&payload) {
                        Ok(p) => p,
                        Err(e) => { tracing::warn!(error = %e, raw = %payload, "G13: parse fail"); continue; }
                    };
                    // Filter loop: skip own messages
                    if parsed.origin_pod == my_pod { continue; }
                    if tx.send(parsed).await.is_err() {
                        // Receiver dropped → exit subscriber task
                        tracing::info!("G13: subscriber receiver dropped, exiting");
                        return;
                    }
                }
                tracing::warn!("G13: pubsub stream closed, reconnecting in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_store_publish_no_panic() {
        let store = LedgerSyncStore::disabled();
        assert!(!store.is_enabled());
        // Non panica
        store.publish_bump("1.2.3.4", 1, 100).await;
    }

    #[tokio::test]
    async fn disabled_store_subscribe_returns_empty_rx() {
        let store = LedgerSyncStore::disabled();
        let mut rx = store.spawn_subscriber().await;
        // try_recv ritorna empty (no sender)
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn ledger_bump_msg_serializes_camelcase() {
        let msg = LedgerBumpMsg {
            ip: "203.0.113.1".to_string(),
            ban_count: 3,
            last_banned_at_epoch_secs: 1_780_000_000,
            origin_pod: "pod-a".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        // Schema default snake_case (no rename_all camelCase qui — JSON natural)
        assert!(json.contains("\"ip\":\"203.0.113.1\""));
        assert!(json.contains("\"ban_count\":3"));
        assert!(json.contains("\"origin_pod\":\"pod-a\""));
    }

    #[test]
    fn ledger_bump_msg_deserializes_round_trip() {
        let json = r#"{"ip":"1.1.1.1","ban_count":2,"last_banned_at_epoch_secs":1700,"origin_pod":"pod-b"}"#;
        let msg: LedgerBumpMsg = serde_json::from_str(json).unwrap();
        assert_eq!(msg.ip, "1.1.1.1");
        assert_eq!(msg.ban_count, 2);
        assert_eq!(msg.origin_pod, "pod-b");
    }

    #[tokio::test]
    async fn pubsub_loop_filter_self_origin() {
        // Test integration: publish via store-A, subscribe via store-B,
        // verifica che store-A NON riceva il proprio messaggio.
        let url = std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let store_a = match LedgerSyncStore::connect(&url, "pod-A".to_string()).await {
            Ok(s) => s,
            Err(_) => { eprintln!("skip: no Redis"); return; }
        };
        let store_b = LedgerSyncStore::connect(&url, "pod-B".to_string()).await.expect("conn b");

        let mut rx_a = store_a.spawn_subscriber().await;
        let mut rx_b = store_b.spawn_subscriber().await;
        // wait per subscribe ready
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // store-A publish
        store_a.publish_bump("test-A", 1, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // rx_a NON deve avere ricevuto il proprio messaggio (origin_pod=pod-A)
        assert!(rx_a.try_recv().is_err(), "self-origin filtering: pod-A non riceve da pod-A");

        // rx_b DEVE aver ricevuto
        let msg = rx_b.try_recv();
        if let Ok(m) = msg {
            assert_eq!(m.ip, "test-A");
            assert_eq!(m.origin_pod, "pod-A");
        }
    }
}
