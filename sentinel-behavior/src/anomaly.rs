//! Anomaly Detection
//!
//! ML-based anomaly detection using:
//! - Statistical outlier detection
//! - Temporal pattern analysis
//! - Sequence anomaly detection

use crate::anomaly_baseline::{tenant_key_from_host, BaselineSnapshot, BaselineStore, BASELINE_DIMENSIONS};
use sentinel_core::{BehaviorConfig, Request, SentinelError};
use std::collections::VecDeque;
use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// Campioni minimi prima che una baseline tenant produca z-score (anti cold-start FP).
const ANOMALY_MIN_SAMPLES: u64 = 100;
/// Cap tenant tracciati nella baseline (oltre → bucket globale). Anti memory-blow.
const ANOMALY_MAX_TENANTS: usize = 4096;

/// Estrae la chiave-tenant dalle header di una request (Host, case-insensitive).
fn tenant_of(request: &Request) -> String {
    let host = request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    tenant_key_from_host(host)
}

/// Types of anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    /// Statistical outlier in request patterns
    StatisticalOutlier,
    /// Unusual timing patterns
    TemporalAnomaly,
    /// Unusual request sequence
    SequenceAnomaly,
}

/// Request features for anomaly detection
#[derive(Debug, Clone)]
struct RequestFeatures {
    /// Request timestamp
    timestamp: Instant,
    /// Path length
    path_length: usize,
    /// Number of query parameters
    query_param_count: usize,
    /// Body size (if any)
    body_size: usize,
    /// Header count
    header_count: usize,
    /// Method ordinal
    method_ordinal: u8,
}

impl RequestFeatures {
    fn from_request(request: &Request) -> Self {
        let body_size = match &request.body {
            Some(sentinel_core::RequestBody::Text(t)) => t.len(),
            Some(sentinel_core::RequestBody::Json(j)) => j.to_string().len(),
            Some(sentinel_core::RequestBody::Binary(b)) => b.len(),
            None => 0,
        };

        let query_param_count = request
            .query_string
            .as_ref()
            .map(|q| q.split('&').count())
            .unwrap_or(0);

        let method_ordinal = match request.method.as_str() {
            "GET" => 0,
            "POST" => 1,
            "PUT" => 2,
            "DELETE" => 3,
            "PATCH" => 4,
            _ => 5,
        };

        Self {
            timestamp: Instant::now(),
            path_length: request.path.len(),
            query_param_count,
            body_size,
            header_count: request.headers.len(),
            method_ordinal,
        }
    }

    fn to_vector(&self) -> Vec<f64> {
        vec![
            self.path_length as f64,
            self.query_param_count as f64,
            self.body_size as f64,
            self.header_count as f64,
            self.method_ordinal as f64,
        ]
    }
}

// NB: la baseline statistica (Welford) vive ora in `anomaly_baseline.rs` (Welford +
// BaselineStore segmentato/persistibile) — SSOT unica, niente più la RunningStats
// duplicata globale-e-volatile che stava qui.

/// Anomaly detector
pub struct AnomalyDetector {
    /// Baseline statistica per-tenant, persistibile (Welford segmentato). Sostituisce
    /// la vecchia RunningStats globale-e-volatile.
    baseline: BaselineStore,
    /// Recent requests for sequence analysis
    recent_requests: RwLock<VecDeque<RequestFeatures>>,
    /// Request intervals for temporal analysis
    request_intervals: RwLock<VecDeque<Duration>>,
    /// Last request time
    last_request: RwLock<Option<Instant>>,
    /// Configuration
    config: BehaviorConfig,
}

impl AnomalyDetector {
    /// Create new anomaly detector
    pub fn new(config: &BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            baseline: BaselineStore::new(BASELINE_DIMENSIONS, ANOMALY_MAX_TENANTS),
            recent_requests: RwLock::new(VecDeque::with_capacity(1000)),
            request_intervals: RwLock::new(VecDeque::with_capacity(100)),
            last_request: RwLock::new(None),
            config: config.clone(),
        })
    }

    /// Detect anomalies in a request
    pub async fn detect(&self, request: &Request) -> Result<Vec<AnomalyType>, SentinelError> {
        let mut anomalies = Vec::new();
        let tenant = tenant_of(request);
        let features = RequestFeatures::from_request(request);
        let vector = features.to_vector();

        // Statistical outlier vs baseline DEL TENANT — valutato PRIMA di osservare
        // (così la richiesta corrente non smorza la propria anomalia).
        if self.is_statistical_outlier(&tenant, &vector) {
            anomalies.push(AnomalyType::StatisticalOutlier);
        }

        // Temporal anomaly detection
        if self.is_temporal_anomaly(&features) {
            anomalies.push(AnomalyType::TemporalAnomaly);
        }

        // Sequence anomaly detection
        if self.is_sequence_anomaly(&features) {
            anomalies.push(AnomalyType::SequenceAnomaly);
        }

        // Learning: aggiorna la baseline del tenant + le finestre temporali/sequenza.
        self.baseline.observe(&tenant, &vector);
        self.update_windows(&features);

        Ok(anomalies)
    }

    /// Check if request is a statistical outlier RISPETTO ALLA BASELINE DEL TENANT.
    /// `None` (baseline non ancora warm) → niente flag: evita falsi positivi a freddo.
    fn is_statistical_outlier(&self, tenant: &str, vector: &[f64]) -> bool {
        match self.baseline.z_score(tenant, vector, ANOMALY_MIN_SAMPLES) {
            Some(z_scores) => z_scores.iter().any(|z| z.abs() > self.config.anomaly_z_threshold),
            None => false,
        }
    }

    /// Check for temporal anomalies
    fn is_temporal_anomaly(&self, features: &RequestFeatures) -> bool {
        let intervals = self.request_intervals.read();

        if intervals.len() < 10 {
            return false;
        }

        // Check request interval
        if let Some(last) = *self.last_request.read() {
            let interval = features.timestamp.duration_since(last);

            // Calculate mean interval
            let total: Duration = intervals.iter().sum();
            let mean_interval = total / intervals.len() as u32;

            // If current interval is significantly different
            if interval.as_millis() > 0 {
                let ratio = mean_interval.as_millis() as f64 / interval.as_millis() as f64;
                // Very fast requests compared to baseline
                if ratio > 10.0 {
                    return true;
                }
            }
        }

        false
    }

    /// Check for sequence anomalies
    fn is_sequence_anomaly(&self, features: &RequestFeatures) -> bool {
        let recent = self.recent_requests.read();

        if recent.len() < 5 {
            return false;
        }

        // Check for suspicious patterns
        // 1. Same endpoint hit repeatedly with same parameters
        let last_five: Vec<_> = recent.iter().rev().take(5).collect();
        if last_five.iter().all(|r| r.path_length == features.path_length) {
            // All same path length - could be automated probing
            let same_body = last_five.iter().all(|r| r.body_size == features.body_size);
            let same_params = last_five
                .iter()
                .all(|r| r.query_param_count == features.query_param_count);
            if same_body && same_params {
                return true;
            }
        }

        // 2. Check for sequential path scanning
        // (detecting automated path enumeration)

        false
    }

    /// Snapshot INCREMENTALE delle baseline tenant modificate dall'ultimo flush
    /// (il server le invia al Portal per la persistenza). At-least-once.
    pub fn baseline_snapshot_dirty(&self) -> Vec<BaselineSnapshot> {
        self.baseline.drain_dirty()
    }

    /// Snapshot COMPLETO di tutte le baseline (flush full periodico / shutdown).
    pub fn baseline_snapshot_all(&self) -> Vec<BaselineSnapshot> {
        self.baseline.snapshot_all()
    }

    /// Restore al boot dalle baseline persistite → niente cold-start a freddo dopo i restart.
    pub fn restore_baseline(&self, snapshots: Vec<BaselineSnapshot>) {
        self.baseline.restore(snapshots);
    }

    /// Numero di tenant con baseline tracciata (diagnostica / test).
    pub fn baseline_tenant_count(&self) -> usize {
        self.baseline.tenant_count()
    }

    /// Aggiorna SOLO le finestre temporali/sequenza. La baseline statistica del tenant
    /// è aggiornata a parte (self.baseline.observe in detect).
    fn update_windows(&self, features: &RequestFeatures) {
        // Update recent requests
        {
            let mut recent = self.recent_requests.write();
            recent.push_back(features.clone());
            if recent.len() > 1000 {
                recent.pop_front();
            }
        }

        // Update intervals
        {
            let mut intervals = self.request_intervals.write();
            let mut last = self.last_request.write();

            if let Some(last_time) = *last {
                let interval = features.timestamp.duration_since(last_time);
                intervals.push_back(interval);
                if intervals.len() > 100 {
                    intervals.pop_front();
                }
            }

            *last = Some(features.timestamp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_detector() -> AnomalyDetector {
        let config = BehaviorConfig::default();
        AnomalyDetector::new(&config).unwrap()
    }

    #[tokio::test]
    async fn test_normal_request() {
        let detector = create_detector();
        let request = Request {
            path: "/api/posts".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let anomalies = detector.detect(&request).await.unwrap();
        // With no baseline, no anomalies detected
        assert!(anomalies.is_empty());
    }

    #[tokio::test]
    async fn test_learning() {
        let detector = create_detector();

        // Train with normal requests
        for _ in 0..50 {
            let request = Request {
                path: "/api/posts".to_string(),
                method: "GET".to_string(),
                ..Default::default()
            };
            let _ = detector.detect(&request).await;
        }

        // La baseline del tenant (qui bucket globale: request senza Host) ha imparato.
        let snaps = detector.baseline_snapshot_all();
        let global = snaps.iter().find(|s| s.tenant == crate::anomaly_baseline::GLOBAL_BUCKET)
            .expect("baseline globale presente dopo 50 richieste");
        assert!(global.stats.count >= 50, "count atteso >=50, got {}", global.stats.count);
    }
}
