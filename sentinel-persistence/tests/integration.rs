//! Integration tests — wiremock simula il Portal API per verificare:
//!  - POST /api/v1/internal/sentinel/threat con header X-Sentinel-Secret
//!  - POST /api/v1/internal/sentinel/ban
//!  - POST /api/v1/internal/sentinel/ban/bump
//!  - Retry exponential su 5xx (almeno 1 retry)
//!  - NO retry su 4xx (drop e log)
//!  - Queue full → drop oldest (no panic)
//!  - Disabled client (no secret) → silent skip
//!  - Payload serializzato camelCase (compatibile Zod schemas TS)

use sentinel_persistence::{
    AnomalyBaselinePayload, BanPayload, BumpPayload, PortalClient, PortalClientConfig,
    ThreatPayload, ThreatSeverity,
};
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_threat() -> ThreatPayload {
    ThreatPayload {
        r#type: "honeypot_hit".to_string(),
        severity: ThreatSeverity::High,
        ip_address: Some("1.2.3.4".to_string()),
        request_id: None,
        confidence: 0.99,
        risk_score: 0.85,
        detection_source: "sentinel_edge".to_string(),
        description: "Honeypot /v1/chat triggered 3 times".to_string(),
        evidence: Some(serde_json::json!({ "hits": 3 })),
        raw_request: None,
        action_taken: Some("banned".to_string()),
        action_details: None,
        ml_features: None,
    }
}

fn make_ban() -> BanPayload {
    BanPayload {
        ip_address: "5.6.7.8".to_string(),
        source: "sentinel_honeypot".to_string(),
        trigger: "honeypot_3_hits".to_string(),
        reason: "Honeypot endpoint triggered".to_string(),
        evidence: None,
        trigger_path: Some("/.env".to_string()),
        trigger_pattern: None,
        user_agent: None,
        request_method: None,
        risk_score: Some(85),
        confidence: Some(0.99),
        duration_hours: 168,
        is_permanent: Some(false),
        country_code: Some("IT".to_string()),
        threat_id: None,
    }
}

#[tokio::test]
async fn threat_delivered_with_correct_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/threat"))
        .and(header("x-sentinel-secret", "test-secret-xyz"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "threatId": "uuid-1"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "test-secret-xyz".to_string(),
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_threat(make_threat());

    // Wait per worker async + retry
    tokio::time::sleep(Duration::from_millis(200)).await;

    // wiremock verifica con .expect(1) — drop server fa assert
}

#[tokio::test]
async fn ban_delivered_with_correct_payload() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/ban"))
        .and(header("x-sentinel-secret", "secret-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "banId": "ban-uuid-1",
            "isNew": true,
            "escalationLevel": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "secret-xyz".to_string(),
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_ban(make_ban());

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn bump_counter_delivered() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/ban/bump"))
        .and(header("x-sentinel-secret", "s"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_bump(BumpPayload {
        ip_address: "1.2.3.4".to_string(),
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn retry_on_5xx_then_success() {
    let server = MockServer::start().await;

    // Prima call → 500
    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/threat"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Successive → 200
    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/threat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
        .expect(1) // attesa: il retry deve riprovare e 1 successo
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        max_retries: 3,
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_threat(make_threat());

    // Backoff min 100ms × retry → aspettiamo 1s tranquilli
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

#[tokio::test]
async fn no_retry_on_4xx_payload_invalid() {
    let server = MockServer::start().await;

    // 400 SOLO una volta — se il client retry erroneamente sarà
    // expectation violation (.expect(1) max).
    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/threat"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "code": "INVALID_PAYLOAD" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        max_retries: 3,
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_threat(make_threat());

    tokio::time::sleep(Duration::from_millis(500)).await;
    // wiremock drop verifica che SOLO 1 call sia arrivata (no retry)
}

#[tokio::test]
async fn disabled_client_silent_no_request() {
    // Server raggiungibile MA il client non ha secret → non deve mai
    // chiamarlo.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0) // ZERO call attese
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: String::new(), // disabilitato
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_threat(make_threat());
    client.send_ban(make_ban());
    client.send_bump(BumpPayload {
        ip_address: "1.2.3.4".to_string(),
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn payload_serialized_camelcase() {
    let server = MockServer::start().await;

    // body_string_contains verifica che il payload reale contenga
    // ipAddress (camelCase) — NON snake_case.
    use wiremock::matchers::body_string_contains;

    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/ban"))
        .and(body_string_contains("\"ipAddress\":\"5.6.7.8\""))
        .and(body_string_contains("\"durationHours\":168"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);
    client.send_ban(make_ban());

    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn timeout_short_does_not_block_sender() {
    // Server lento (5s) — client timeout 200ms → fail-fast
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        timeout: Duration::from_millis(200),
        max_retries: 0,
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);

    let start = std::time::Instant::now();
    client.send_threat(make_threat());
    let elapsed = start.elapsed();
    // send_threat è fire-and-forget → return immediato
    assert!(
        elapsed < Duration::from_millis(50),
        "send_threat blocked for {:?}",
        elapsed
    );
}

#[tokio::test]
async fn queue_overflow_drops_oldest_no_panic() {
    let server = MockServer::start().await;

    // Server lento → coda riempie
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;

    let cfg = PortalClientConfig {
        base_url: server.uri(),
        secret: "s".to_string(),
        queue_capacity: 4, // molto piccolo per forzare overflow
        timeout: Duration::from_secs(3),
        ..Default::default()
    };
    let client = PortalClient::spawn(cfg);

    // Spara 100 eventi → almeno alcuni drop, ma NESSUN panic
    for _ in 0..100 {
        client.send_threat(make_threat());
    }

    // Test passa se non panicchiamo
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// ─── Flush-at-shutdown: send BLOCCANTE (awaitable) della baseline anomaly ───
// Il flush periodico è fire-and-forget; allo shutdown serve la GARANZIA che il POST
// sia completato prima dell'exit. Questi test pinnano il contratto del metodo usato
// da shutdown_signal() nel server.

fn make_baseline() -> AnomalyBaselinePayload {
    AnomalyBaselinePayload {
        tenant: "acme".to_string(),
        stats: serde_json::json!({
            "count": 300, "mean": [1.0, 2.0], "m2": [3.0, 4.0], "min": [0.0, 0.0], "max": [9.0, 9.0]
        }),
    }
}

#[tokio::test]
async fn anomaly_baseline_blocking_awaits_and_returns_ok_on_200() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/internal/sentinel/anomaly-baseline"))
        .and(header("x-sentinel-secret", "test-secret-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "written": 1 })))
        .expect(1) // .expect(1) sul drop verifica che il POST sia DAVVERO partito (non perso)
        .mount(&server)
        .await;

    let client = PortalClient::spawn(PortalClientConfig {
        base_url: server.uri(),
        secret: "test-secret-xyz".to_string(),
        ..Default::default()
    });
    // A differenza del fire-and-forget, l'await GARANTISCE il POST completato qui.
    let res = client
        .send_anomaly_baselines_blocking(vec![make_baseline()])
        .await;
    assert!(res.is_ok(), "blocking send deve ritornare Ok su 200, got {res:?}");
}

#[tokio::test]
async fn anomaly_baseline_blocking_empty_is_ok_noop() {
    // batch vuoto → Ok immediato, nessun HTTP (base_url volutamente irraggiungibile).
    let client = PortalClient::spawn(PortalClientConfig {
        base_url: "http://127.0.0.1:1".to_string(),
        secret: "x".repeat(32),
        ..Default::default()
    });
    assert!(client.send_anomaly_baselines_blocking(vec![]).await.is_ok());
}

#[tokio::test]
async fn anomaly_baseline_blocking_disabled_client_is_ok_noop() {
    // no secret → client disabilitato → Ok senza toccare la rete.
    let client = PortalClient::spawn(PortalClientConfig {
        secret: String::new(),
        ..Default::default()
    });
    assert!(client
        .send_anomaly_baselines_blocking(vec![make_baseline()])
        .await
        .is_ok());
}
