//! SENTINEL Metrics
//!
//! Prometheus-compatible metrics for monitoring.

use sentinel_core::{Action, LayerRiskScore as RiskScore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Global metrics instance
static METRICS: Metrics = Metrics::new();

/// Metrics collector
pub struct Metrics {
    // Request counts
    requests_total: AtomicU64,
    requests_allowed: AtomicU64,
    requests_blocked: AtomicU64,
    requests_challenged: AtomicU64,
    requests_rate_limited: AtomicU64,

    // Risk level counts
    risk_none: AtomicU64,
    risk_low: AtomicU64,
    risk_medium: AtomicU64,
    risk_high: AtomicU64,
    risk_critical: AtomicU64,

    // Latency buckets (microseconds)
    latency_under_100us: AtomicU64,
    latency_under_500us: AtomicU64,
    latency_under_1ms: AtomicU64,
    latency_under_5ms: AtomicU64,
    latency_under_10ms: AtomicU64,
    latency_over_10ms: AtomicU64,

    // Total latency for average calculation
    latency_total_us: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_challenged: AtomicU64::new(0),
            requests_rate_limited: AtomicU64::new(0),

            risk_none: AtomicU64::new(0),
            risk_low: AtomicU64::new(0),
            risk_medium: AtomicU64::new(0),
            risk_high: AtomicU64::new(0),
            risk_critical: AtomicU64::new(0),

            latency_under_100us: AtomicU64::new(0),
            latency_under_500us: AtomicU64::new(0),
            latency_under_1ms: AtomicU64::new(0),
            latency_under_5ms: AtomicU64::new(0),
            latency_under_10ms: AtomicU64::new(0),
            latency_over_10ms: AtomicU64::new(0),

            latency_total_us: AtomicU64::new(0),
        }
    }

    fn record(&self, latency: Duration, risk_score: &RiskScore, action: &Action) {
        // Increment total
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Record action
        match action {
            Action::Allow => self.requests_allowed.fetch_add(1, Ordering::Relaxed),
            Action::Block { .. } => self.requests_blocked.fetch_add(1, Ordering::Relaxed),
            Action::Challenge(_) => self.requests_challenged.fetch_add(1, Ordering::Relaxed),
            Action::RateLimit { .. } => self.requests_rate_limited.fetch_add(1, Ordering::Relaxed),
        };

        // Record risk level
        match risk_score.level {
            sentinel_core::RiskLevel::None => self.risk_none.fetch_add(1, Ordering::Relaxed),
            sentinel_core::RiskLevel::Low => self.risk_low.fetch_add(1, Ordering::Relaxed),
            sentinel_core::RiskLevel::Medium => self.risk_medium.fetch_add(1, Ordering::Relaxed),
            sentinel_core::RiskLevel::High => self.risk_high.fetch_add(1, Ordering::Relaxed),
            sentinel_core::RiskLevel::Critical => self.risk_critical.fetch_add(1, Ordering::Relaxed),
        };

        // Record latency
        let latency_us = latency.as_micros() as u64;
        self.latency_total_us.fetch_add(latency_us, Ordering::Relaxed);

        if latency_us < 100 {
            self.latency_under_100us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 500 {
            self.latency_under_500us.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 1000 {
            self.latency_under_1ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 5000 {
            self.latency_under_5ms.fetch_add(1, Ordering::Relaxed);
        } else if latency_us < 10000 {
            self.latency_under_10ms.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_over_10ms.fetch_add(1, Ordering::Relaxed);
        };
    }

    /// Get average latency in microseconds
    fn avg_latency_us(&self) -> u64 {
        let total = self.requests_total.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        self.latency_total_us.load(Ordering::Relaxed) / total
    }
}

/// Record a request
pub fn record_request(latency: Duration, risk_score: &RiskScore, action: &Action) {
    METRICS.record(latency, risk_score, action);
}

/// Export metrics in Prometheus format
pub fn export_prometheus() -> String {
    let mut output = String::new();

    // Request counts
    output.push_str("# HELP sentinel_requests_total Total number of requests processed\n");
    output.push_str("# TYPE sentinel_requests_total counter\n");
    output.push_str(&format!(
        "sentinel_requests_total {}\n",
        METRICS.requests_total.load(Ordering::Relaxed)
    ));

    output.push_str("# HELP sentinel_requests_by_action Requests by action taken\n");
    output.push_str("# TYPE sentinel_requests_by_action counter\n");
    output.push_str(&format!(
        "sentinel_requests_by_action{{action=\"allow\"}} {}\n",
        METRICS.requests_allowed.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_action{{action=\"block\"}} {}\n",
        METRICS.requests_blocked.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_action{{action=\"challenge\"}} {}\n",
        METRICS.requests_challenged.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_action{{action=\"rate_limit\"}} {}\n",
        METRICS.requests_rate_limited.load(Ordering::Relaxed)
    ));

    // Risk levels
    output.push_str("# HELP sentinel_requests_by_risk Requests by risk level\n");
    output.push_str("# TYPE sentinel_requests_by_risk counter\n");
    output.push_str(&format!(
        "sentinel_requests_by_risk{{level=\"none\"}} {}\n",
        METRICS.risk_none.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_risk{{level=\"low\"}} {}\n",
        METRICS.risk_low.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_risk{{level=\"medium\"}} {}\n",
        METRICS.risk_medium.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_risk{{level=\"high\"}} {}\n",
        METRICS.risk_high.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_requests_by_risk{{level=\"critical\"}} {}\n",
        METRICS.risk_critical.load(Ordering::Relaxed)
    ));

    // Latency histogram
    output.push_str("# HELP sentinel_latency_us_bucket Request latency buckets in microseconds\n");
    output.push_str("# TYPE sentinel_latency_us_bucket histogram\n");
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"100\"}} {}\n",
        METRICS.latency_under_100us.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"500\"}} {}\n",
        METRICS.latency_under_100us.load(Ordering::Relaxed)
            + METRICS.latency_under_500us.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"1000\"}} {}\n",
        METRICS.latency_under_100us.load(Ordering::Relaxed)
            + METRICS.latency_under_500us.load(Ordering::Relaxed)
            + METRICS.latency_under_1ms.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"5000\"}} {}\n",
        METRICS.latency_under_100us.load(Ordering::Relaxed)
            + METRICS.latency_under_500us.load(Ordering::Relaxed)
            + METRICS.latency_under_1ms.load(Ordering::Relaxed)
            + METRICS.latency_under_5ms.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"10000\"}} {}\n",
        METRICS.latency_under_100us.load(Ordering::Relaxed)
            + METRICS.latency_under_500us.load(Ordering::Relaxed)
            + METRICS.latency_under_1ms.load(Ordering::Relaxed)
            + METRICS.latency_under_5ms.load(Ordering::Relaxed)
            + METRICS.latency_under_10ms.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "sentinel_latency_us_bucket{{le=\"+Inf\"}} {}\n",
        METRICS.requests_total.load(Ordering::Relaxed)
    ));

    // Average latency
    output.push_str("# HELP sentinel_latency_avg_us Average request latency in microseconds\n");
    output.push_str("# TYPE sentinel_latency_avg_us gauge\n");
    output.push_str(&format!(
        "sentinel_latency_avg_us {}\n",
        METRICS.avg_latency_us()
    ));

    output
}

/// Get metrics as JSON
pub fn export_json() -> serde_json::Value {
    serde_json::json!({
        "requests": {
            "total": METRICS.requests_total.load(Ordering::Relaxed),
            "allowed": METRICS.requests_allowed.load(Ordering::Relaxed),
            "blocked": METRICS.requests_blocked.load(Ordering::Relaxed),
            "challenged": METRICS.requests_challenged.load(Ordering::Relaxed),
            "rate_limited": METRICS.requests_rate_limited.load(Ordering::Relaxed),
        },
        "risk_levels": {
            "none": METRICS.risk_none.load(Ordering::Relaxed),
            "low": METRICS.risk_low.load(Ordering::Relaxed),
            "medium": METRICS.risk_medium.load(Ordering::Relaxed),
            "high": METRICS.risk_high.load(Ordering::Relaxed),
            "critical": METRICS.risk_critical.load(Ordering::Relaxed),
        },
        "latency": {
            "avg_us": METRICS.avg_latency_us(),
            "buckets": {
                "under_100us": METRICS.latency_under_100us.load(Ordering::Relaxed),
                "under_500us": METRICS.latency_under_500us.load(Ordering::Relaxed),
                "under_1ms": METRICS.latency_under_1ms.load(Ordering::Relaxed),
                "under_5ms": METRICS.latency_under_5ms.load(Ordering::Relaxed),
                "under_10ms": METRICS.latency_under_10ms.load(Ordering::Relaxed),
                "over_10ms": METRICS.latency_over_10ms.load(Ordering::Relaxed),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_export() {
        let output = export_prometheus();
        assert!(output.contains("sentinel_requests_total"));
        assert!(output.contains("sentinel_requests_by_action"));
        assert!(output.contains("sentinel_latency_us_bucket"));
    }

    #[test]
    fn test_json_export() {
        let output = export_json();
        assert!(output.get("requests").is_some());
        assert!(output.get("risk_levels").is_some());
        assert!(output.get("latency").is_some());
    }
}
