//! Persistable, per-tenant anomaly baseline — Welford online statistics.
//!
//! # Perché questo modulo esiste
//! L'anomaly detector (`anomaly.rs`) impara la "forma normale" delle richieste via
//! Welford online. PRIMA aveva due buchi che lo rendevano quasi inutile in produzione:
//!   1. **Volatile**: una sola `RunningStats` in RAM → azzerata a OGNI restart del WAF
//!      (frequenti) → non accumulava mai, e ripartiva cieca per `min_samples` richieste.
//!   2. **Globale e grezza**: un'unica baseline su TUTTO il traffico di TUTTI i tenant →
//!      chi sta nella media globale è invisibile; un tenant atipico = falsi positivi.
//!
//! Questo modulo è la SSOT della baseline: Welford **serializzabile** (resume-able da
//! count+mean+m2), **segmentata per-tenant**, con snapshot per la persistenza (bridge →
//! Portal → tabella `sentinel_anomaly_baseline`) e restore al boot (niente più cold-start
//! a freddo, niente più amnesia da restart).
//!
//! È PURO (nessun I/O): la persistenza vive nel chiamante (sentinel-server) che fa lo
//! snapshot periodico e il restore al boot — così il modulo resta testabile in isolamento.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

/// Dimensioni del vettore feature (path_length, query_param_count, body_size,
/// header_count, method_ordinal). SSOT condivisa con `anomaly.rs::RequestFeatures`.
pub const BASELINE_DIMENSIONS: usize = 5;

/// Bucket usato quando l'Host non identifica un tenant noto (richieste senza host,
/// IP diretto, health-check). Tenuto separato così non "sporca" le baseline tenant.
pub const GLOBAL_BUCKET: &str = "__global__";

/// Statistiche online di Welford — `count`/`mean`/`m2` bastano a RIPRENDERE il calcolo
/// dopo un restore (min/max sono accessori diagnostici). Serializable per la persistenza.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Welford {
    pub count: u64,
    pub mean: Vec<f64>,
    pub m2: Vec<f64>,
    pub min: Vec<f64>,
    pub max: Vec<f64>,
}

impl Welford {
    pub fn new(dimensions: usize) -> Self {
        Self {
            count: 0,
            mean: vec![0.0; dimensions],
            m2: vec![0.0; dimensions],
            min: vec![f64::MAX; dimensions],
            max: vec![f64::MIN; dimensions],
        }
    }

    /// Aggiorna lo stato con un'osservazione. Robusto: ignora valori non-finiti
    /// (NaN/Inf) per-dimensione (un body_size corrotto non deve avvelenare la media)
    /// e una lunghezza errata del vettore (difesa, non panic).
    pub fn update(&mut self, values: &[f64]) {
        if values.len() != self.mean.len() {
            return; // dimensione incompatibile → no-op difensivo (mai panic sul hot-path)
        }
        self.count += 1;
        let n = self.count as f64;
        // Iterazione su 5 array PARALLELI (value + mean/m2/min/max) via zip mutabile:
        // idiomatica e clippy-clean (no needless_range_loop), nessun panic da index.
        for ((((v, mean_i), m2_i), min_i), max_i) in values
            .iter()
            .zip(self.mean.iter_mut())
            .zip(self.m2.iter_mut())
            .zip(self.min.iter_mut())
            .zip(self.max.iter_mut())
        {
            if !v.is_finite() {
                continue; // NaN/Inf: non avvelenare la baseline
            }
            let delta = *v - *mean_i;
            *mean_i += delta / n;
            let delta2 = *v - *mean_i;
            *m2_i += delta * delta2;
            *min_i = min_i.min(*v);
            *max_i = max_i.max(*v);
        }
    }

    /// Deviazione standard campionaria per-dimensione. `1.0` se < 2 campioni
    /// (evita divisione per zero e z-score infiniti durante il warm-up).
    pub fn std_dev(&self) -> Vec<f64> {
        if self.count < 2 {
            return vec![1.0; self.mean.len()];
        }
        let denom = (self.count - 1) as f64;
        // `.max(0.0)` PRIMA di sqrt: m2 è una somma di quadrati e DEVE essere >= 0, ma
        // una cancellazione floating-point (o un restore corrotto) può renderlo
        // leggermente negativo → `sqrt(neg)` = NaN → z-score NaN → detector morto in
        // silenzio. In Rust `f64::max` IGNORA NaN (ritorna l'altro arg), quindi
        // `.max(0.0)` neutralizza SIA il negativo SIA un eventuale NaN → mai NaN in output.
        self.m2.iter().map(|m| (m / denom).max(0.0).sqrt()).collect()
    }

    /// z-score per-dimensione. `0.0` dove std_dev è 0 (dimensione costante → nessuna
    /// anomalia possibile) o dove il valore non è finito.
    pub fn z_score(&self, values: &[f64]) -> Vec<f64> {
        if values.len() != self.mean.len() {
            return vec![0.0; self.mean.len()];
        }
        let std = self.std_dev();
        values
            .iter()
            .zip(self.mean.iter())
            .zip(std.iter())
            .map(|((v, m), s)| {
                if v.is_finite() && *s > 0.0 {
                    (v - m) / s
                } else {
                    0.0
                }
            })
            .collect()
    }

    /// `true` se ci sono abbastanza campioni perché la baseline sia significativa.
    pub fn is_warm(&self, min_samples: u64) -> bool {
        self.count >= min_samples
    }
}

/// Snapshot persistibile di UNA baseline tenant. È ciò che il bridge invia al Portal
/// e ciò che il Portal restituisce al boot per il restore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineSnapshot {
    pub tenant: String,
    pub stats: Welford,
}

/// Store delle baseline segmentate per tenant. Concorrente (DashMap), con dirty-tracking
/// per snapshot incrementali (solo i tenant cambiati dall'ultimo flush vengono inviati).
pub struct BaselineStore {
    dimensions: usize,
    /// Cap sul numero di tenant tracciati (anti memory-blow da Host header arbitrari).
    max_tenants: usize,
    segments: DashMap<String, Welford>,
    /// Tenant modificati dall'ultimo `drain_dirty()` (snapshot incrementale).
    dirty: DashMap<String, ()>,
    has_dirty: AtomicBool,
}

impl BaselineStore {
    pub fn new(dimensions: usize, max_tenants: usize) -> Self {
        Self {
            dimensions,
            max_tenants,
            segments: DashMap::new(),
            dirty: DashMap::new(),
            has_dirty: AtomicBool::new(false),
        }
    }

    /// Osserva una richiesta per `tenant` aggiornando la sua baseline. Crea il segmento
    /// se assente (entro il cap). Marca il tenant dirty per il prossimo snapshot.
    pub fn observe(&self, tenant: &str, features: &[f64]) {
        // Scelta della chiave SENZA ricorsione: tenant noto → sé stesso; tenant nuovo
        // entro il cap → sé stesso; tenant nuovo oltre il cap → bucket globale (sink).
        // GLOBAL_BUCKET è sempre scrivibile (è il +1 di overflow, mai allocazione illimitata).
        let key: String = if self.segments.contains_key(tenant) || self.segments.len() < self.max_tenants {
            tenant.to_string()
        } else {
            GLOBAL_BUCKET.to_string()
        };
        {
            let mut e = self
                .segments
                .entry(key.clone())
                .or_insert_with(|| Welford::new(self.dimensions));
            e.update(features);
        }
        // BOUNDED: `key` è sempre un tenant già presente, uno entro max_tenants, o
        // GLOBAL_BUCKET → dirty.len() <= segments.len() <= max_tenants + 1. drain_dirty
        // lo svuota a ogni flush. Nessuna crescita illimitata.
        self.dirty.insert(key, ());
        self.has_dirty.store(true, Ordering::Relaxed);
    }

    /// z-score della richiesta rispetto alla baseline del tenant. `None` se la baseline
    /// non è ancora "warm" (< `min_samples`) → il chiamante NON deve flaggare a freddo.
    pub fn z_score(&self, tenant: &str, features: &[f64], min_samples: u64) -> Option<Vec<f64>> {
        let seg = self.segments.get(tenant)?;
        if !seg.is_warm(min_samples) {
            return None;
        }
        Some(seg.z_score(features))
    }

    /// Restore al boot: semina i segmenti dagli snapshot persistiti. Scarta snapshot con
    /// dimensione incompatibile (schema feature cambiato) → ripartono puliti, mai panic.
    /// NON marca dirty (è stato appena caricato, non c'è nulla da ri-salvare).
    pub fn restore(&self, snapshots: Vec<BaselineSnapshot>) {
        for snap in snapshots {
            // Cap HARD anche sul restore: una risposta portal anomala (o compromessa) non
            // deve poter allocare oltre max_tenants. I già-presenti si aggiornano sempre;
            // i nuovi solo entro il cap.
            if !self.segments.contains_key(&snap.tenant) && self.segments.len() >= self.max_tenants {
                continue;
            }
            if snap.stats.mean.len() == self.dimensions && snap.stats.m2.len() == self.dimensions {
                self.segments.insert(snap.tenant, snap.stats);
            }
        }
    }

    /// Estrae gli snapshot dei tenant DIRTY e azzera il dirty-set (snapshot incrementale).
    ///
    /// SEMANTICA REALE (no aspirazionale): è **best-effort / at-most-once per singolo
    /// flush**. Il drain rimuove subito le chiavi dal dirty-set; il chiamante
    /// (`send_anomaly_baselines`, fire-and-forget) NON ri-marca dirty se il POST fallisce,
    /// quindi quel batch è perso. Ma la baseline è uno stato CUMULATIVO: alla prossima
    /// `observe()` di quel tenant la chiave torna dirty e l'ULTIMO stato (più aggiornato)
    /// viene re-inviato → nessuna perdita permanente finché il tenant ha traffico. Per i
    /// tenant divenuti silenti subito dopo un flush fallito, lo stato resta comunque in RAM
    /// e viene ri-persistito al primo restart→boot→osservazione successiva.
    pub fn drain_dirty(&self) -> Vec<BaselineSnapshot> {
        if !self.has_dirty.swap(false, Ordering::Relaxed) {
            return Vec::new();
        }
        let keys: Vec<String> = self.dirty.iter().map(|e| e.key().clone()).collect();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            self.dirty.remove(&k);
            if let Some(seg) = self.segments.get(&k) {
                out.push(BaselineSnapshot { tenant: k, stats: seg.clone() });
            }
        }
        out
    }

    /// Snapshot COMPLETO (tutti i segmenti) — per un flush full periodico/shutdown.
    pub fn snapshot_all(&self) -> Vec<BaselineSnapshot> {
        self.segments
            .iter()
            .map(|e| BaselineSnapshot { tenant: e.key().clone(), stats: e.value().clone() })
            .collect()
    }

    pub fn tenant_count(&self) -> usize {
        self.segments.len()
    }
}

/// Estrae la chiave-tenant dall'Host header: `<slug>.app.<...>` → `slug`.
/// Strip della porta, lowercase, fallback `GLOBAL_BUCKET` se host assente/non-tenant.
/// Pubblica + pura → testabile e riusabile (SSOT della segmentazione).
pub fn tenant_key_from_host(host: Option<&str>) -> String {
    let Some(h) = host else { return GLOBAL_BUCKET.to_string() };
    let h = h.trim().to_ascii_lowercase();
    let h = h.split(':').next().unwrap_or(&h); // strip :port
    // Primo label come slug del tenant, MA solo se è un subdomain (≥3 label) — un apex
    // come "example.com" non è un tenant → bucket globale.
    let labels: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() >= 3 {
        let slug = labels[0];
        if !slug.is_empty() && slug != "www" {
            return slug.to_string();
        }
    }
    GLOBAL_BUCKET.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats(a: f64, b: f64, c: f64, d: f64, e: f64) -> Vec<f64> {
        vec![a, b, c, d, e]
    }

    // ── Welford: correttezza statistica ──────────────────────────────────────
    #[test]
    fn welford_mean_and_stddev_match_known_values() {
        let mut w = Welford::new(1);
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.update(&[v]);
        }
        assert_eq!(w.count, 8);
        assert!((w.mean[0] - 5.0).abs() < 1e-9, "mean atteso 5.0, got {}", w.mean[0]);
        // stddev CAMPIONARIA (n-1): varianza pop = 4 → var campionaria = 32/7 ≈ 4.571 → sd ≈ 2.138
        assert!((w.std_dev()[0] - 2.1380899).abs() < 1e-4, "sd got {}", w.std_dev()[0]);
        assert_eq!(w.min[0], 2.0);
        assert_eq!(w.max[0], 9.0);
    }

    // ── ANTI-REGRESSIONE: std_dev MAI NaN su m2 negativo/NaN (.max(0.0)) ──────
    // Un m2 leggermente negativo (cancellazione FP) o NaN (restore corrotto) faceva
    // `sqrt(neg)` = NaN → z-score NaN → detector morto in silenzio. Mutation-verify:
    // togliendo `.max(0.0)` da std_dev questo test diventa rosso.
    #[test]
    fn std_dev_is_never_nan_on_negative_or_nan_m2() {
        let mut w = Welford::new(3);
        w.count = 10; // >= 2 → ramo di calcolo reale (non il fallback warm-up)
        w.mean = vec![1.0, 2.0, 3.0];
        // m2[0] negativo (FP cancellation), m2[1] NaN (corruzione), m2[2] valido.
        w.m2 = vec![-0.0001, f64::NAN, 9.0];
        let sd = w.std_dev();
        assert_eq!(sd.len(), 3);
        for (i, s) in sd.iter().enumerate() {
            assert!(s.is_finite(), "std_dev[{i}] deve essere finito, got {s}");
            assert!(*s >= 0.0, "std_dev[{i}] deve essere >= 0, got {s}");
        }
        // il negativo e il NaN collassano a 0; la dimensione valida resta corretta.
        assert_eq!(sd[0], 0.0);
        assert_eq!(sd[1], 0.0);
        assert!((sd[2] - (9.0_f64 / 9.0).sqrt()).abs() < 1e-12);

        // E il z-score a valle resta finito (non propaga NaN).
        let z = w.z_score(&[5.0, 5.0, 5.0]);
        assert!(z.iter().all(|v| v.is_finite()), "z-score non deve mai essere NaN: {z:?}");
    }

    // ── IL CONTRACT CHIAVE: snapshot → restore → equivalenza esatta ───────────
    // È il cuore della persistenza: una baseline serializzata e ricaricata DEVE
    // produrre gli STESSI mean/std/z-score di una mai-interrotta. Se questo si rompe,
    // il "ricordare tra restart" è una bugia.
    #[test]
    fn restore_from_snapshot_is_statistically_identical() {
        let mut live = Welford::new(BASELINE_DIMENSIONS);
        for i in 0..500u64 {
            live.update(&feats(i as f64 % 13.0, (i % 5) as f64, (i % 1000) as f64, 7.0, 2.0));
        }
        // round-trip JSON (come farà il bridge → Portal → JSONB → boot). NB: il contract
        // è "STATISTICAMENTE identica", NON bit-exact: il JSON (e il JSONB Postgres a valle)
        // può arrotondare di 1 ULP un mean accumulato → irrilevante per un z-score. Asserire
        // l'uguaglianza bit-a-bit sarebbe un test fragile che non riflette il sistema reale.
        let json = serde_json::to_string(&live).unwrap();
        let restored: Welford = serde_json::from_str(&json).unwrap();
        assert_eq!(live.count, restored.count, "count DEVE essere esatto");
        for i in 0..BASELINE_DIMENSIONS {
            assert!((live.mean[i] - restored.mean[i]).abs() <= 1e-9 * live.mean[i].abs().max(1.0),
                "mean[{i}] drift oltre 1 ULP: {} vs {}", live.mean[i], restored.mean[i]);
            assert!((live.std_dev()[i] - restored.std_dev()[i]).abs() <= 1e-6 * live.std_dev()[i].abs().max(1.0),
                "std_dev[{i}] non equivalente");
        }
        // i z-score post-restore coincidono entro tolleranza → decisioni identiche
        let probe = feats(99.0, 99.0, 99999.0, 99.0, 9.0);
        let (zl, zr) = (live.z_score(&probe), restored.z_score(&probe));
        for i in 0..BASELINE_DIMENSIONS {
            assert!((zl[i] - zr[i]).abs() <= 1e-6, "z_score[{i}] divergente dopo restore: {} vs {}", zl[i], zr[i]);
        }
    }

    // ── Bug-bounty: input rotti non avvelenano la baseline / non panico ──────
    #[test]
    fn nan_inf_and_dim_mismatch_are_ignored() {
        let mut w = Welford::new(3);
        w.update(&[1.0, 2.0, 3.0]);
        let mean_before = w.mean.clone();
        w.update(&[f64::NAN, f64::INFINITY, f64::NEG_INFINITY]); // count++, ma valori scartati per-dim
        w.update(&[1.0, 2.0]); // dim mismatch → no-op totale
        assert_eq!(w.count, 2, "dim-mismatch non deve incrementare count");
        // i valori non-finiti non hanno spostato la media verso NaN
        assert!(w.mean.iter().all(|m| m.is_finite()), "media inquinata da NaN/Inf");
        // la media è cambiata pochissimo (count salito a 2 con valori scartati → /n)
        assert!(w.mean.iter().zip(&mean_before).all(|(a, b)| (a - b).abs() < 1.0));
    }

    #[test]
    fn zscore_no_panic_on_zero_variance_and_mismatch() {
        let mut w = Welford::new(2);
        for _ in 0..10 {
            w.update(&[5.0, 5.0]); // varianza 0
        }
        let z = w.z_score(&[5.0, 100.0]);
        assert_eq!(z[0], 0.0, "varianza 0 → z 0 (no Inf)");
        assert_eq!(w.z_score(&[1.0]), vec![0.0, 0.0], "dim mismatch → vettore 0, no panic");
    }

    // ── Store: isolamento per-tenant ─────────────────────────────────────────
    #[test]
    fn per_tenant_isolation_no_cross_contamination() {
        let s = BaselineStore::new(BASELINE_DIMENSIONS, 100);
        // Jitter realistico (varianza > 0, altrimenti std=0 → nessun outlier rilevabile):
        // acme ~ richieste piccole, globex ~ richieste grandi, entrambe con rumore.
        for i in 0..200u64 {
            let j = (i % 5) as f64;
            s.observe("acme", &feats(10.0 + j, 1.0, 100.0 + j * 2.0, 5.0, 1.0));
        }
        for i in 0..200u64 {
            let j = (i % 7) as f64;
            s.observe("globex", &feats(500.0 + j, 50.0 + j, 90000.0 + j * 10.0, 40.0, 4.0));
        }
        // una richiesta "acme-normale" è normale per acme e CLAMOROSAMENTE anomala per globex.
        let acme_req = feats(11.0, 1.0, 102.0, 5.0, 1.0);
        let z_acme = s.z_score("acme", &acme_req, 100).unwrap();
        assert!(z_acme.iter().all(|z| z.abs() < 3.0), "acme-normale non deve essere outlier per acme: {z_acme:?}");
        let z_globex = s.z_score("globex", &acme_req, 100).unwrap();
        assert!(z_globex.iter().any(|z| z.abs() > 3.0), "acme-normale DEVE essere outlier per globex: {z_globex:?}");
    }

    // ── Store: cold-start gating (non flagga sotto min_samples) ───────────────
    #[test]
    fn cold_start_returns_none_until_warm() {
        let s = BaselineStore::new(BASELINE_DIMENSIONS, 100);
        for _ in 0..50 {
            s.observe("t", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        }
        assert!(s.z_score("t", &feats(1.0, 1.0, 1.0, 1.0, 1.0), 100).is_none(), "sotto soglia → None");
        assert!(s.z_score("ignoto", &feats(1.0, 1.0, 1.0, 1.0, 1.0), 100).is_none(), "tenant assente → None");
        for _ in 0..60 {
            s.observe("t", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        }
        assert!(s.z_score("t", &feats(1.0, 1.0, 1.0, 1.0, 1.0), 100).is_some(), "≥ soglia → Some");
    }

    // ── Store: restore semina i segmenti + warm immediato (no cold-start) ─────
    #[test]
    fn restore_seeds_segments_and_avoids_cold_start() {
        let src = BaselineStore::new(BASELINE_DIMENSIONS, 100);
        for _ in 0..300 {
            src.observe("acme", &feats(10.0, 1.0, 100.0, 5.0, 1.0));
        }
        let snaps = src.snapshot_all();
        let fresh = BaselineStore::new(BASELINE_DIMENSIONS, 100);
        fresh.restore(snaps);
        // subito warm dopo il restore (niente 100 richieste di ri-apprendimento)
        assert!(fresh.z_score("acme", &feats(10.0, 1.0, 100.0, 5.0, 1.0), 100).is_some());
        assert_eq!(fresh.tenant_count(), 1);
    }

    #[test]
    fn restore_drops_incompatible_dimensions() {
        let store = BaselineStore::new(5, 100);
        store.restore(vec![BaselineSnapshot {
            tenant: "x".into(),
            stats: Welford::new(3), // schema vecchio a 3 dim
        }]);
        assert_eq!(store.tenant_count(), 0, "snapshot dim-incompatibile scartato, mai panic");
    }

    // ── Store: dirty-tracking incrementale ───────────────────────────────────
    #[test]
    fn drain_dirty_returns_only_changed_then_clears() {
        let s = BaselineStore::new(BASELINE_DIMENSIONS, 100);
        s.observe("a", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        s.observe("b", &feats(2.0, 2.0, 2.0, 2.0, 2.0));
        let d1 = s.drain_dirty();
        assert_eq!(d1.len(), 2, "primo drain: 2 tenant dirty");
        assert!(s.drain_dirty().is_empty(), "secondo drain senza modifiche: vuoto");
        s.observe("a", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        let d3 = s.drain_dirty();
        assert_eq!(d3.len(), 1, "solo 'a' modificato");
        assert_eq!(d3[0].tenant, "a");
    }

    // ── Store: cap tenant → confluisce nel bucket globale (anti memory-blow) ──
    #[test]
    fn over_cap_tenants_fold_into_global_bucket() {
        let s = BaselineStore::new(BASELINE_DIMENSIONS, 2);
        s.observe("t1", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        s.observe("t2", &feats(1.0, 1.0, 1.0, 1.0, 1.0));
        // t3 oltre il cap → va nel global, non crea un 3° segmento oltre il cap+global
        for _ in 0..5 {
            s.observe("t3", &feats(9.0, 9.0, 9.0, 9.0, 9.0));
        }
        assert!(s.tenant_count() <= 3, "cap rispettato (2 + global)");
        assert!(s.snapshot_all().iter().any(|x| x.tenant == GLOBAL_BUCKET));
    }

    // ── tenant_key_from_host: parsing/edge-case ──────────────────────────────
    #[test]
    fn host_parsing_extracts_slug_else_global() {
        assert_eq!(tenant_key_from_host(Some("acme.app.example.net")), "acme");
        assert_eq!(tenant_key_from_host(Some("ACME.APP.example.com:443")), "acme"); // lowercase + strip port
        assert_eq!(tenant_key_from_host(Some("example.com")), GLOBAL_BUCKET); // apex (2 label)
        assert_eq!(tenant_key_from_host(Some("www.example.com")), GLOBAL_BUCKET); // www non è tenant
        assert_eq!(tenant_key_from_host(None), GLOBAL_BUCKET);
        assert_eq!(tenant_key_from_host(Some("")), GLOBAL_BUCKET);
        assert_eq!(tenant_key_from_host(Some("   ")), GLOBAL_BUCKET);
    }
}

