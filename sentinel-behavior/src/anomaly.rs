//! Anomaly Detection
//!
//! ML-based anomaly detection using:
//! - Statistical outlier detection
//! - Temporal pattern analysis
//! - Sequence anomaly detection

use sentinel_core::{BehaviorConfig, Request, SentinelError};
use std::collections::VecDeque;
use std::sync::RwLock;
use std::time::{Duration, Instant};

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

/// Running statistics for anomaly detection
#[derive(Debug, Clone)]
struct RunningStats {
    count: u64,
    mean: Vec<f64>,
    m2: Vec<f64>, // For variance calculation
    min: Vec<f64>,
    max: Vec<f64>,
}

impl RunningStats {
    fn new(dimensions: usize) -> Self {
        Self {
            count: 0,
            mean: vec![0.0; dimensions],
            m2: vec![0.0; dimensions],
            min: vec![f64::MAX; dimensions],
            max: vec![f64::MIN; dimensions],
        }
    }

    fn update(&mut self, values: &[f64]) {
        self.count += 1;
        let n = self.count as f64;

        for i in 0..values.len() {
            let delta = values[i] - self.mean[i];
            self.mean[i] += delta / n;
            let delta2 = values[i] - self.mean[i];
            self.m2[i] += delta * delta2;

            self.min[i] = self.min[i].min(values[i]);
            self.max[i] = self.max[i].max(values[i]);
        }
    }

    fn std_dev(&self) -> Vec<f64> {
        if self.count < 2 {
            return vec![1.0; self.mean.len()];
        }
        self.m2.iter().map(|m| (m / (self.count as f64 - 1.0)).sqrt()).collect()
    }

    fn z_score(&self, values: &[f64]) -> Vec<f64> {
        let std_dev = self.std_dev();
        values
            .iter()
            .zip(self.mean.iter())
            .zip(std_dev.iter())
            .map(|((v, m), s)| if *s > 0.0 { (v - m) / s } else { 0.0 })
            .collect()
    }
}

/// Anomaly detector
pub struct AnomalyDetector {
    /// Running statistics
    stats: RwLock<RunningStats>,
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
            stats: RwLock::new(RunningStats::new(5)),
            recent_requests: RwLock::new(VecDeque::with_capacity(1000)),
            request_intervals: RwLock::new(VecDeque::with_capacity(100)),
            last_request: RwLock::new(None),
            config: config.clone(),
        })
    }

    /// Detect anomalies in a request
    pub async fn detect(&self, request: &Request) -> Result<Vec<AnomalyType>, SentinelError> {
        let mut anomalies = Vec::new();
        let features = RequestFeatures::from_request(request);

        // Statistical outlier detection
        if self.is_statistical_outlier(&features) {
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

        // Update statistics for learning
        self.update_stats(&features);

        Ok(anomalies)
    }

    /// Check if request is statistical outlier
    fn is_statistical_outlier(&self, features: &RequestFeatures) -> bool {
        let stats = self.stats.read().unwrap();

        // Need enough data for meaningful stats
        if stats.count < 100 {
            return false;
        }

        let vector = features.to_vector();
        let z_scores = stats.z_score(&vector);

        // Check if any dimension exceeds threshold (typically 3 std devs)
        z_scores.iter().any(|z| z.abs() > self.config.anomaly_z_threshold)
    }

    /// Check for temporal anomalies
    fn is_temporal_anomaly(&self, features: &RequestFeatures) -> bool {
        let intervals = self.request_intervals.read().unwrap();

        if intervals.len() < 10 {
            return false;
        }

        // Check request interval
        if let Some(last) = *self.last_request.read().unwrap() {
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
        let recent = self.recent_requests.read().unwrap();

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

    /// Update statistics with new request
    fn update_stats(&self, features: &RequestFeatures) {
        // Update running stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.update(&features.to_vector());
        }

        // Update recent requests
        {
            let mut recent = self.recent_requests.write().unwrap();
            recent.push_back(features.clone());
            if recent.len() > 1000 {
                recent.pop_front();
            }
        }

        // Update intervals
        {
            let mut intervals = self.request_intervals.write().unwrap();
            let mut last = self.last_request.write().unwrap();

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

        // Stats should be updated
        let stats = detector.stats.read().unwrap();
        assert!(stats.count >= 50);
    }
}
