//! G19 (2026-06-02): SLA observability per-tenant.
//!
//! Aggrega per ogni tenant_id (lookup da cf-connecting-ip → workspace_id
//! futuro o IP-bucket nel frattempo):
//! - request_count / second-window 1min
//! - latency p50/p95/p99 percentile via reservoir sampling
//! - action breakdown: allow / challenge / block / rate_limit
//! - risk level distribution: none / low / medium / high / critical
//!
//! Endpoint: GET /sla → JSON con top tenant + percentiles.

use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tenant identifier — per ora IP-based; futuro: workspace_id lookup
pub type TenantId = String;

/// Per-tenant stats. Atomic counters per concurrent updates.
#[derive(Debug)]
pub struct TenantStats {
    pub request_count: AtomicU64,
    pub allow_count: AtomicU64,
    pub challenge_count: AtomicU64,
    pub block_count: AtomicU64,
    pub rate_limit_count: AtomicU64,
    pub risk_none: AtomicU64,
    pub risk_low: AtomicU64,
    pub risk_medium: AtomicU64,
    pub risk_high: AtomicU64,
    pub risk_critical: AtomicU64,
    pub latency_sum_us: AtomicU64,
    /// Reservoir per percentile p50/p95/p99 — 1000 sample max
    pub latency_samples: parking_lot::Mutex<Vec<u64>>,
    pub last_seen: parking_lot::Mutex<Instant>,
}

impl Default for TenantStats {
    fn default() -> Self {
        Self {
            request_count: AtomicU64::new(0),
            allow_count: AtomicU64::new(0),
            challenge_count: AtomicU64::new(0),
            block_count: AtomicU64::new(0),
            rate_limit_count: AtomicU64::new(0),
            risk_none: AtomicU64::new(0),
            risk_low: AtomicU64::new(0),
            risk_medium: AtomicU64::new(0),
            risk_high: AtomicU64::new(0),
            risk_critical: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_samples: parking_lot::Mutex::new(Vec::with_capacity(1000)),
            last_seen: parking_lot::Mutex::new(Instant::now()),
        }
    }
}

const MAX_RESERVOIR_SAMPLES: usize = 1000;

/// Global per-tenant store.
pub struct SlaStore {
    tenants: DashMap<TenantId, Arc<TenantStats>>,
}

impl SlaStore {
    pub fn new() -> Self {
        Self { tenants: DashMap::new() }
    }

    /// Record un request completato per il tenant.
    pub fn record(
        &self,
        tenant: TenantId,
        latency_us: u64,
        action: ActionKind,
        risk_level: RiskKind,
    ) {
        let entry = self.tenants.entry(tenant).or_insert_with(|| Arc::new(TenantStats::default()));
        let stats = entry.value();
        stats.request_count.fetch_add(1, Ordering::Relaxed);
        match action {
            ActionKind::Allow => stats.allow_count.fetch_add(1, Ordering::Relaxed),
            ActionKind::Challenge => stats.challenge_count.fetch_add(1, Ordering::Relaxed),
            ActionKind::Block => stats.block_count.fetch_add(1, Ordering::Relaxed),
            ActionKind::RateLimit => stats.rate_limit_count.fetch_add(1, Ordering::Relaxed),
        };
        match risk_level {
            RiskKind::None => stats.risk_none.fetch_add(1, Ordering::Relaxed),
            RiskKind::Low => stats.risk_low.fetch_add(1, Ordering::Relaxed),
            RiskKind::Medium => stats.risk_medium.fetch_add(1, Ordering::Relaxed),
            RiskKind::High => stats.risk_high.fetch_add(1, Ordering::Relaxed),
            RiskKind::Critical => stats.risk_critical.fetch_add(1, Ordering::Relaxed),
        };
        stats.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        // Reservoir sampling: tieni primi 1000, poi swap random
        {
            let mut samples = stats.latency_samples.lock(); // parking_lot: guard diretto
            if samples.len() < MAX_RESERVOIR_SAMPLES {
                samples.push(latency_us);
            } else {
                // Random replacement (cheap deterministic via counter mod)
                let idx = (stats.request_count.load(Ordering::Relaxed) as usize) % MAX_RESERVOIR_SAMPLES;
                samples[idx] = latency_us;
            }
        }
        *stats.last_seen.lock() = Instant::now();
    }

    /// Snapshot per top N tenant by request_count
    pub fn snapshot_top(&self, top_n: usize) -> Vec<TenantSnapshot> {
        let mut all: Vec<TenantSnapshot> = self.tenants.iter()
            .map(|e| {
                let t = e.value();
                let req = t.request_count.load(Ordering::Relaxed);
                let sum = t.latency_sum_us.load(Ordering::Relaxed);
                let mean = if req > 0 { sum / req } else { 0 };
                let (p50, p95, p99) = compute_percentiles(&t.latency_samples.lock());
                TenantSnapshot {
                    tenant: e.key().clone(),
                    request_count: req,
                    allow: t.allow_count.load(Ordering::Relaxed),
                    challenge: t.challenge_count.load(Ordering::Relaxed),
                    block: t.block_count.load(Ordering::Relaxed),
                    rate_limit: t.rate_limit_count.load(Ordering::Relaxed),
                    risk_none: t.risk_none.load(Ordering::Relaxed),
                    risk_low: t.risk_low.load(Ordering::Relaxed),
                    risk_medium: t.risk_medium.load(Ordering::Relaxed),
                    risk_high: t.risk_high.load(Ordering::Relaxed),
                    risk_critical: t.risk_critical.load(Ordering::Relaxed),
                    latency_mean_us: mean,
                    latency_p50_us: p50,
                    latency_p95_us: p95,
                    latency_p99_us: p99,
                }
            })
            .collect();
        all.sort_by(|a, b| b.request_count.cmp(&a.request_count));
        all.truncate(top_n);
        all
    }

    pub fn cleanup_idle(&self, max_age: Duration) {
        let now = Instant::now();
        self.tenants.retain(|_, t| now.duration_since(*t.last_seen.lock()) < max_age);
    }

    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ActionKind { Allow, Challenge, Block, RateLimit }

#[derive(Debug, Clone, Copy)]
pub enum RiskKind { None, Low, Medium, High, Critical }

impl From<sentinel_core::RiskLevel> for RiskKind {
    /// Mappa 1:1 il livello di rischio del motore sul bucket SLA. Esaustivo
    /// per costruzione: se `RiskLevel` guadagna una variante, il compilatore
    /// rompe qui (niente catch-all che mascheri un buco di osservabilità).
    fn from(level: sentinel_core::RiskLevel) -> Self {
        match level {
            sentinel_core::RiskLevel::None => RiskKind::None,
            sentinel_core::RiskLevel::Low => RiskKind::Low,
            sentinel_core::RiskLevel::Medium => RiskKind::Medium,
            sentinel_core::RiskLevel::High => RiskKind::High,
            sentinel_core::RiskLevel::Critical => RiskKind::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantSnapshot {
    pub tenant: TenantId,
    pub request_count: u64,
    pub allow: u64,
    pub challenge: u64,
    pub block: u64,
    pub rate_limit: u64,
    pub risk_none: u64,
    pub risk_low: u64,
    pub risk_medium: u64,
    pub risk_high: u64,
    pub risk_critical: u64,
    pub latency_mean_us: u64,
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_p99_us: u64,
}

/// Calcola p50/p95/p99 da samples (clona + sort)
fn compute_percentiles(samples: &[u64]) -> (u64, u64, u64) {
    if samples.is_empty() { return (0, 0, 0); }
    let mut sorted: Vec<u64> = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let p = |pct: f64| -> u64 {
        let idx = ((n as f64) * pct).floor() as usize;
        sorted[idx.min(n - 1)]
    };
    (p(0.50), p(0.95), p(0.99))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_snapshot_single_tenant() {
        let store = SlaStore::new();
        for _ in 0..10 {
            store.record("tenant-a".to_string(), 500, ActionKind::Allow, RiskKind::None);
        }
        let top = store.snapshot_top(10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].request_count, 10);
        assert_eq!(top[0].allow, 10);
        assert_eq!(top[0].latency_mean_us, 500);
    }

    #[test]
    fn snapshot_top_n_orders_by_request_count() {
        let store = SlaStore::new();
        for _ in 0..5 { store.record("low".to_string(), 100, ActionKind::Allow, RiskKind::None); }
        for _ in 0..100 { store.record("high".to_string(), 100, ActionKind::Allow, RiskKind::None); }
        for _ in 0..50 { store.record("mid".to_string(), 100, ActionKind::Allow, RiskKind::None); }
        let top = store.snapshot_top(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].tenant, "high");
        assert_eq!(top[1].tenant, "mid");
    }

    #[test]
    fn risk_level_breakdown_aggregates() {
        let store = SlaStore::new();
        store.record("a".to_string(), 100, ActionKind::Block, RiskKind::Critical);
        store.record("a".to_string(), 100, ActionKind::Allow, RiskKind::None);
        store.record("a".to_string(), 100, ActionKind::Challenge, RiskKind::High);
        let top = store.snapshot_top(10);
        let a = &top[0];
        assert_eq!(a.block, 1);
        assert_eq!(a.allow, 1);
        assert_eq!(a.challenge, 1);
        assert_eq!(a.risk_critical, 1);
        assert_eq!(a.risk_high, 1);
        assert_eq!(a.risk_none, 1);
    }

    #[test]
    fn percentile_p50_p95_p99_reasonable() {
        let samples: Vec<u64> = (1..=100).collect();
        let (p50, p95, p99) = compute_percentiles(&samples);
        assert!((48..=52).contains(&p50), "p50 ~50, got {p50}");
        assert!((94..=96).contains(&p95), "p95 ~95, got {p95}");
        assert!((98..=100).contains(&p99), "p99 ~99, got {p99}");
    }

    #[test]
    fn percentile_empty_samples_returns_zero() {
        let (p50, p95, p99) = compute_percentiles(&[]);
        assert_eq!((p50, p95, p99), (0, 0, 0));
    }

    #[test]
    fn risk_kind_from_risk_level_maps_every_variant() {
        // Mapping esaustivo 1:1. Se RiskLevel guadagna una variante, `From`
        // non compila più (niente catch-all) e questo test la copre tutta.
        use sentinel_core::RiskLevel;
        let cases = [
            (RiskLevel::None, RiskKind::None),
            (RiskLevel::Low, RiskKind::Low),
            (RiskLevel::Medium, RiskKind::Medium),
            (RiskLevel::High, RiskKind::High),
            (RiskLevel::Critical, RiskKind::Critical),
        ];
        for (level, expected) in cases {
            // discriminante via Debug: RiskKind non è PartialEq e non vogliamo
            // aggiungere derive solo per il test.
            assert_eq!(
                format!("{:?}", RiskKind::from(level)),
                format!("{expected:?}"),
                "mapping errato per {level:?}"
            );
        }
    }

    #[test]
    fn risk_breakdown_riceve_i_livelli_mappati_dal_motore() {
        // Integrazione: i RiskKind derivati da RiskLevel via From alimentano
        // davvero i contatori per-livello dello snapshot.
        use sentinel_core::RiskLevel;
        let store = SlaStore::new();
        store.record("t".into(), 100, ActionKind::Block, RiskLevel::Critical.into());
        store.record("t".into(), 100, ActionKind::RateLimit, RiskLevel::Medium.into());
        store.record("t".into(), 100, ActionKind::Allow, RiskLevel::None.into());
        let a = &store.snapshot_top(10)[0];
        assert_eq!(a.risk_critical, 1);
        assert_eq!(a.risk_medium, 1);
        assert_eq!(a.risk_none, 1);
    }

    #[test]
    fn cleanup_idle_removes_old_tenants() {
        let store = SlaStore::new();
        store.record("stale".to_string(), 100, ActionKind::Allow, RiskKind::None);
        assert_eq!(store.tenant_count(), 1);
        // Force last_seen to 100s ago
        for entry in store.tenants.iter() {
            *entry.value().last_seen.lock() = Instant::now() - Duration::from_secs(100);
        }
        store.cleanup_idle(Duration::from_secs(30));
        assert_eq!(store.tenant_count(), 0);
    }
}
