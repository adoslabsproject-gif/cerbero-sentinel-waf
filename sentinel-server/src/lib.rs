//! SENTINEL Server (v2.0.0)
//!
//! HTTP server exposing SENTINEL WAF functionality:
//! - REST API for configuration
//! - Middleware integration
//! - Health checks
//! - Metrics endpoint
//! - Identity graph + Intent detection + JA3 TLS fingerprinting
//! - Global memory pressure guard (N4)
//! - Periodic behavioral cleanup

pub mod middleware;
pub mod api;
pub mod metrics;

use sentinel_core::{SentinelConfig, SentinelError};
use sentinel_edge::EdgeShield;
use sentinel_edge::ja3::{analyze_ja3, Ja3Classification};
use sentinel_neural::NeuralDefense;
use sentinel_neural::ml::HotReloadableModel;
use sentinel_behavior::BehavioralAnalysis;
use sentinel_response::ResponseLayer;
use sentinel_persistence::{PortalClient, PortalClientConfig};
use dashmap::DashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Cache key: IP + UA hash (not just IP — attackers rotate UAs)
#[derive(Clone, Eq, PartialEq, Hash)]
struct CacheKey {
    ip: std::net::IpAddr,
    ua_hash: u64,
}

/// Cached analysis result
struct CachedResult {
    action: sentinel_core::Action,
    /// Livello di rischio EFFETTIVO calcolato dai layer per questa decisione.
    /// Cachato accanto all'action così un cache-hit ripropaga lo stesso risk
    /// allo SLA store (altrimenti il cache-hit perderebbe il dato → falso None).
    risk: sentinel_core::RiskLevel,
    created_at: Instant,
}

/// Esito completo di `Sentinel::process`: l'azione da applicare PIÙ il livello
/// di rischio effettivo che i layer hanno calcolato per arrivarci. Il risk è
/// dato di prima classe (non derivabile dall'`Action`: una `Allow` può venire
/// da risk None o Low; un `Block` da High o Critical) e serve all'osservabilità
/// SLA per-tenant.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: sentinel_core::Action,
    pub risk: sentinel_core::RiskLevel,
}

const CACHE_TTL: Duration = Duration::from_secs(5);
const CACHE_TTL_DEFENSE: Duration = Duration::from_secs(15);
const MAX_CACHE_SIZE: usize = 50_000;
/// Benign sampling: 1 richiesta pulita ogni N viene campionata come negativo per il training.
///
/// Storia: 200 → 20 (2026-07-07) → 2 su contatore DEDICATO (2026-08-02).
/// Il difetto non era solo il valore: il campionamento usava il contatore GLOBALE delle
/// richieste, quindi per produrre un campione doveva capitare che la N-esima richiesta in
/// assoluto fosse ANCHE una richiesta pulita arrivata fino al full-path — due condizioni
/// indipendenti. Risultato misurato: 51 campioni in un mese, contro i ~2/giorno attesi.
/// Ora il contatore avanza SOLO sui candidati veri (Allow sul full-path), quindi 1-ogni-N
/// significa davvero 1 ogni N candidati.
///
/// Perché il tasso alto conta: i negativi devono venire dallo STESSO percorso dei positivi,
/// altrimenti si riconoscono dalla provenienza invece che dal comportamento. Il full-path è
/// l'unico posto dove tutti i segnali (timing, anomalia, ASN) esistono davvero.
const BENIGN_SAMPLE_EVERY: u64 = 2;

/// Cleanup interval for behavioral data (every 60s)
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Hash a string using DefaultHasher
fn hash_ua(ua: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ua.hash(&mut hasher);
    hasher.finish()
}

/// G21.2 (2026-06-11): le tre regole di protezione che il breaker può
/// sospendere INDIPENDENTEMENTE l'una dall'altra.
///
/// NON include la hard-WAF (pattern CVE/RCE/webshell deterministici): quella
/// resta SEMPRE attiva anche in safe-mode, perché non genera falsi positivi e
/// non ha senso disabilitarla mai. Il safe-mode granulare riguarda solo il
/// blocking *basato sul rischio* dei tre layer di analisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionLayer {
    /// Layer 1: rate-limit, IP intel, GeoIP, DDoS, fingerprint TLS.
    Edge,
    /// Layer 2: web-attack RegexSet, prompt injection, toxicity ONNX.
    Neural,
    /// Layer 3: sessione, cross-IP, identity graph, intent, timing + il
    /// risk combinato della response determination.
    Behavioral,
}

impl ProtectionLayer {
    /// Tutti i layer, ordine stabile (per snapshot/iterazione deterministica).
    pub const ALL: [ProtectionLayer; 3] = [Self::Edge, Self::Neural, Self::Behavioral];

    /// Etichetta stabile usata in JSON/route/log. Contratto: NON cambiare le
    /// stringhe senza aggiornare i consumer (admin UI, endpoint).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Neural => "neural",
            Self::Behavioral => "behavioral",
        }
    }

    /// Parse inverso di `as_str` (per le route `/safe-mode/layer/{layer}`).
    /// `"full"` è accettato come alias di `behavioral` (la response
    /// determination del layer 3 era loggata storicamente come "full").
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "edge" => Some(Self::Edge),
            "neural" => Some(Self::Neural),
            "behavioral" | "behaviour" | "behavior" | "full" => Some(Self::Behavioral),
            _ => None,
        }
    }
}

/// G21.2: registro safe-mode PER-LAYER (sostituisce il booleano globale N5).
///
/// Ogni layer di protezione può essere sospeso indipendentemente: quando il
/// breaker rileva un cascade di falsi positivi attribuibile a UN layer (es.
/// la regola behavioral-4xx impazzita), sospende SOLO quel layer e lascia
/// edge/neural/honeypot a bloccare normalmente. Pre-G21.2 l'unico switch era
/// globale: un cascade su una regola spegneva TUTTA la difesa soft.
pub struct SafeModeRegistry {
    edge: AtomicBool,
    neural: AtomicBool,
    behavioral: AtomicBool,
}

impl SafeModeRegistry {
    /// Crea il registro. `all_suspended=true` = boot in safe-mode totale
    /// (env `SENTINEL_SAFE_MODE`).
    fn new(all_suspended: bool) -> Self {
        Self {
            edge: AtomicBool::new(all_suspended),
            neural: AtomicBool::new(all_suspended),
            behavioral: AtomicBool::new(all_suspended),
        }
    }

    fn cell(&self, layer: ProtectionLayer) -> &AtomicBool {
        match layer {
            ProtectionLayer::Edge => &self.edge,
            ProtectionLayer::Neural => &self.neural,
            ProtectionLayer::Behavioral => &self.behavioral,
        }
    }

    /// True se il layer è sospeso (blocking off, logging on).
    pub fn is_suspended(&self, layer: ProtectionLayer) -> bool {
        self.cell(layer).load(Ordering::Relaxed)
    }

    /// Sospende un layer. Ritorna `true` se è stata una transizione
    /// attivo→sospeso (utile per loggare/alertare una sola volta).
    pub fn suspend(&self, layer: ProtectionLayer) -> bool {
        !self.cell(layer).swap(true, Ordering::Relaxed)
    }

    /// Riattiva un layer. Ritorna `true` se è stata una transizione
    /// sospeso→attivo.
    pub fn resume(&self, layer: ProtectionLayer) -> bool {
        self.cell(layer).swap(false, Ordering::Relaxed)
    }

    /// Sospende TUTTI i layer (safe-mode globale legacy / manuale).
    pub fn suspend_all(&self) {
        for l in ProtectionLayer::ALL {
            self.cell(l).store(true, Ordering::Relaxed);
        }
    }

    /// Riattiva TUTTI i layer.
    pub fn resume_all(&self) {
        for l in ProtectionLayer::ALL {
            self.cell(l).store(false, Ordering::Relaxed);
        }
    }

    /// True se ALMENO un layer è sospeso (compat col vecchio `safe_mode_active`).
    pub fn any_suspended(&self) -> bool {
        ProtectionLayer::ALL.iter().any(|&l| self.is_suspended(l))
    }

    /// Elenco dei layer attualmente sospesi (per health/status/log).
    pub fn suspended_layers(&self) -> Vec<&'static str> {
        ProtectionLayer::ALL
            .iter()
            .filter(|&&l| self.is_suspended(l))
            .map(|&l| l.as_str())
            .collect()
    }
}

/// SENTINEL WAF v2.0.0 - Complete security system
///
/// Layers:
///   1. Edge Shield (rate limit, IP intel, GeoIP, DDoS, fingerprint, JA3)
///   2. Neural Defense (web attacks 155 RegexSet, prompt injection 51, toxicity ONNX)
///   3. Behavioral Analysis (session, cross-IP, identity graph, intent detection, timing)
///   4. Response Layer (action determination, bans, challenges, escalation)
pub struct Sentinel {
    /// Configuration
    _config: SentinelConfig,
    /// Layer 1: Edge Shield
    edge: Arc<EdgeShield>,
    /// Layer 2: Neural Defense
    neural: Arc<NeuralDefense>,
    /// Layer 3: Behavioral Analysis (v2.0.0: includes cross-IP, identity, intent, timing)
    behavior: Arc<BehavioralAnalysis>,
    /// Layer 4: Response Layer
    response: Arc<ResponseLayer>,
    /// IP+UA micro-cache (WI-3b): avoids full pipeline for repeated requests
    analysis_cache: DashMap<CacheKey, CachedResult>,
    /// Threat classifier (XGBoost → ONNX) with hot-reload + shadow mode (WI-6)
    threat_classifier: Arc<HotReloadableModel>,
    /// v2.0.0: Request counter for periodic tasks (cleanup, model check)
    request_counter: AtomicU64,
    /// v2.0.0: Timestamp of last cleanup
    last_cleanup: parking_lot::Mutex<Instant>,
    /// Contatore dei soli CANDIDATI al campionamento benigno (richieste pulite arrivate al
    /// full-path). Separato da `request_counter` perché quello globale rendeva il tasso di
    /// campionamento imprevedibile — vedi BENIGN_SAMPLE_EVERY.
    benign_counter: AtomicU64,
    /// Accordo fra meta-modello e layer: l'unica base concreta per decidere se e quando
    /// dare peso al modello nelle decisioni. Vedi ShadowAgreement.
    shadow_agreement: ShadowAgreement,
    /// G21.2 (2026-06-11): safe-mode PER-LAYER (sostituisce il booleano N5).
    /// Quando un layer è sospeso, le sue decisioni di blocking diventano
    /// log-only; gli altri layer continuano a bloccare. Hard-WAF sempre attiva.
    safe_mode: SafeModeRegistry,
}

/// Soglia oltre la quale la probabilità del meta-modello viene letta come "minaccia".
/// Usata SOLO per misurare l'accordo coi layer, non per decidere alcunché.
const THREAT_CLASSIFIER_DECISION_THRESHOLD: f32 = 0.5;

/// Accordo fra il meta threat_classifier e i layer che decidono davvero.
///
/// Perché esiste (2026-08-04): il codice prometteva «si promuove quando validato» senza
/// che esistesse alcun modo di sapere se il modello fosse validato. Restava un log da
/// leggere a mano, quindi la promozione non sarebbe mai potuta avvenire su basi concrete.
///
/// Qui si contano i quattro quadranti fra ciò che dice il modello e ciò che i layer hanno
/// deciso. Non è una misura di verità — i layer sbagliano a loro volta — ma risponde
/// all'unica domanda che conta prima di dare peso a un modello: *quanto spesso direbbe
/// qualcosa di diverso, e in quale direzione?*
///
/// In particolare `model_flags_allowed`: quante volte il modello griderebbe "attacco" su
/// traffico che oggi passa. È il numero da guardare prima di promuoverlo, perché è la
/// stima diretta di quanti clienti verrebbero bannati per errore.
#[derive(Debug, Default)]
struct ShadowAgreement {
    /// Predizioni totali eseguite dal modello in shadow.
    total: AtomicU64,
    /// Modello: minaccia — layer: bloccato. Accordo sul lato "attacco".
    agree_threat: AtomicU64,
    /// Modello: benigno — layer: passato. Accordo sul lato "pulito".
    agree_clean: AtomicU64,
    /// ⚠️ Modello: minaccia — layer: PASSATO. Sono i potenziali falsi positivi.
    model_flags_allowed: AtomicU64,
    /// Modello: benigno — layer: bloccato. Il modello si perderebbe qualcosa che i layer prendono.
    model_misses_blocked: AtomicU64,
}

impl ShadowAgreement {
    fn record(&self, threat_prob: f32, layers_blocked: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let model_says_threat = threat_prob >= THREAT_CLASSIFIER_DECISION_THRESHOLD;
        let counter = match (model_says_threat, layers_blocked) {
            (true, true) => &self.agree_threat,
            (false, false) => &self.agree_clean,
            (true, false) => &self.model_flags_allowed,
            (false, true) => &self.model_misses_blocked,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ShadowAgreementStats {
        let total = self.total.load(Ordering::Relaxed);
        let flags_allowed = self.model_flags_allowed.load(Ordering::Relaxed);
        let mut stats = ShadowAgreementStats {
            total,
            agree_threat: self.agree_threat.load(Ordering::Relaxed),
            agree_clean: self.agree_clean.load(Ordering::Relaxed),
            model_flags_allowed: flags_allowed,
            model_misses_blocked: self.model_misses_blocked.load(Ordering::Relaxed),
            // Quota di traffico oggi consentito che il modello bloccherebbe: la stima
            // diretta del danno che farebbe se promosso adesso.
            flag_rate_on_allowed: if total == 0 { 0.0 } else { flags_allowed as f64 / total as f64 },
            promotion_ready: false,
            promotion_reason: String::new(),
        };
        let (ready, reason) = promotion_verdict(&stats);
        stats.promotion_ready = ready;
        stats.promotion_reason = reason;
        stats
    }
}

/// Fotografia dell'accordo, esposta da `/health` per poter decidere sui NUMERI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowAgreementStats {
    pub total: u64,
    pub agree_threat: u64,
    pub agree_clean: u64,
    pub model_flags_allowed: u64,
    pub model_misses_blocked: u64,
    pub flag_rate_on_allowed: f64,
    /// Il modello è pronto a contribuire alle decisioni? Vedi [`promotion_verdict`].
    pub promotion_ready: bool,
    /// Perché sì o perché no, in una frase leggibile.
    pub promotion_reason: String,
}

/// Osservazioni minime prima di poter dire qualcosa sul comportamento del modello.
/// Sotto questa soglia qualunque percentuale è rumore.
const PROMOTION_MIN_OBSERVATIONS: u64 = 1_000;
/// Quota massima di traffico OGGI CONSENTITO che il modello segnalerebbe come minaccia.
/// È la stima diretta dei clienti che verrebbero bannati per errore: oltre l'1% il
/// modello non entra nelle decisioni, punto.
const PROMOTION_MAX_FLAG_RATE_ON_ALLOWED: f64 = 0.01;

/// Criterio ESPLICITO di promozione da osservatore a contributore delle decisioni.
///
/// Prima esisteva solo un commento — «si promuove quando validato» — senza che «validato»
/// significasse niente di verificabile e senza che nessuno lo misurasse. Una promessa
/// scritta in un commento non è un meccanismo: questa funzione la rende una condizione
/// che si può leggere, testare e mostrare in `/health`.
///
/// Volutamente severa e asimmetrica, perché lo è il costo: un attacco mancato può ancora
/// essere fermato dagli altri quattro layer, un cliente bannato per errore no.
#[must_use]
fn promotion_verdict(s: &ShadowAgreementStats) -> (bool, String) {
    if s.total < PROMOTION_MIN_OBSERVATIONS {
        return (
            false,
            format!(
                "osservazioni insufficienti: {}/{} — con così pochi dati qualunque percentuale è rumore",
                s.total, PROMOTION_MIN_OBSERVATIONS
            ),
        );
    }
    if s.flag_rate_on_allowed > PROMOTION_MAX_FLAG_RATE_ON_ALLOWED {
        return (
            false,
            format!(
                "segnalerebbe come minaccia il {:.2}% del traffico oggi consentito \
                 (max {:.2}%): sono clienti veri che verrebbero bloccati",
                s.flag_rate_on_allowed * 100.0,
                PROMOTION_MAX_FLAG_RATE_ON_ALLOWED * 100.0
            ),
        );
    }
    if s.agree_threat == 0 {
        return (
            false,
            "non ha mai concordato coi layer su una minaccia reale: non c'è prova che \
             riconosca gli attacchi, solo che non disturba il traffico pulito"
                .to_string(),
        );
    }
    (
        true,
        format!(
            "{} osservazioni, segnala il {:.2}% del traffico consentito, {} accordi su minacce reali",
            s.total,
            s.flag_rate_on_allowed * 100.0,
            s.agree_threat
        ),
    )
}

/// Segnali prodotti dal layer behavioral (timing dal tracker + anomalia).
///
/// Esistono SOLO dopo che `behavior.analyze`/`behavior.record` sono girati, cioè sul
/// full-path: ai fast-path edge/neural il layer viene saltato per latenza e questi valori
/// non vengono calcolati affatto. Stanno insieme in una struct — invece di essere tre
/// parametri sciolti — proprio per rendere irrappresentabile lo stato incoerente
/// "burst misurato ma anomalia no", che è il modo in cui gli zeri inventati erano
/// entrati nel dataset.
#[derive(Debug, Clone, Copy)]
struct BehaviorSignals {
    burst_score: f32,
    inter_request_stddev: f32,
}

impl Sentinel {
    /// Create new SENTINEL v2.0.0 instance
    pub fn new(config: SentinelConfig) -> Result<Self, SentinelError> {
        // Threat classifier model directory from env or default
        let model_dir = std::env::var("SENTINEL_ONNX_MODEL_DIR")
            .unwrap_or_else(|_| "/opt/zeliai/ml/models/sentinel".to_string());

        let threat_classifier = Arc::new(HotReloadableModel::new(&model_dir)?);

        // N5: Check safe mode from env
        let safe_mode = std::env::var("SENTINEL_SAFE_MODE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if safe_mode {
            tracing::warn!("[SAFE_MODE] Sentinel starting in safe mode — blocking disabled except hard WAF");
        }

        // ─── Env-driven neural overrides (prompt injection tuning per deployment) ───
        // SENTINEL_PROMPT_INJECTION_THRESHOLD overrides the ML score threshold.
        // Default 0.7. Lower (e.g. 0.55) for LLM-input where false-negatives
        // cost more than false-positives. Higher (e.g. 0.85) for high-volume
        // generic WAF use where false-positives are user-visible.
        let mut config = config;
        if let Ok(raw) = std::env::var("SENTINEL_PROMPT_INJECTION_THRESHOLD") {
            if let Ok(v) = raw.parse::<f32>() {
                if (0.0..=1.0).contains(&v) {
                    tracing::info!(
                        old = config.neural.prompt_injection_threshold,
                        new = v,
                        "Overriding prompt_injection_threshold from env"
                    );
                    config.neural.prompt_injection_threshold = v;
                } else {
                    tracing::warn!(value = v, "SENTINEL_PROMPT_INJECTION_THRESHOLD out of [0,1], ignoring");
                }
            }
        }
        if let Ok(raw) = std::env::var("SENTINEL_PROMPT_INJECTION_ENABLED") {
            let enabled = raw == "true" || raw == "1";
            tracing::info!(enabled, "Overriding prompt_injection_enabled from env");
            config.neural.prompt_injection_enabled = enabled;
        }
        if let Ok(raw) = std::env::var("SENTINEL_TOXICITY_THRESHOLD") {
            if let Ok(v) = raw.parse::<f32>() {
                if (0.0..=1.0).contains(&v) {
                    config.neural.toxicity_threshold = v;
                }
            }
        }

        // Bootstrap Portal persistence client (fire-and-forget).
        // Quando SENTINEL_INTERNAL_SECRET è vuoto il client è no-op e
        // ResponseLayer fallback su log-only legacy. Vedi
        // apps/sentinel/sentinel-persistence/src/lib.rs.
        let portal_client = PortalClient::spawn(PortalClientConfig::from_env());

        Ok(Self {
            edge: Arc::new(EdgeShield::new(config.edge.clone())?),
            neural: Arc::new(NeuralDefense::new(config.neural.clone())?),
            behavior: Arc::new(BehavioralAnalysis::new(config.behavior.clone())?),
            response: Arc::new(ResponseLayer::with_persistence(
                config.response.clone(),
                portal_client,
            )?),
            analysis_cache: DashMap::with_capacity(1000),
            threat_classifier,
            request_counter: AtomicU64::new(0),
            benign_counter: AtomicU64::new(0),
            shadow_agreement: ShadowAgreement::default(),
            last_cleanup: parking_lot::Mutex::new(Instant::now()),
            safe_mode: SafeModeRegistry::new(safe_mode),
            _config: config,
        })
    }

    /// Costruisce il record RAW 18-feature (threat_features) per il training del
    /// threat_classifier, dai segnali disponibili nel decision-path: Request (path/UA/query/
    /// method/timestamp), lo score di layer (risk/severity/behavioral→anomaly) e la geo
    /// (is_datacenter via ASN). Allegato alla riga security_threats sul ban (mig 098).
    ///
    /// ⚠️ Ciò che il percorso NON ha misurato viaggia come `None` → `null` nel JSON.
    /// Prima ai fast-path edge/neural si passava `0.0` per burst/stddev "perché il layer
    /// behavior non è ancora girato": uno zero che il trainer leggeva come "nessuna
    /// raffica", indistinguibile da una misura vera. Un buco dichiarato vale più di un
    /// numero inventato — e il guard anti-leakage sorveglia che i buchi non siano
    /// sistematicamente su una classe sola.
    fn build_ml_features(
        &self,
        request: &sentinel_core::Request,
        score: &sentinel_core::LayerRiskScore,
        source: &str,
        // `None` ai fast-path edge/neural: il layer behavior non è ancora girato, quindi
        // NESSUNO dei suoi segnali esiste (≠ valgono zero). Sono raggruppati apposta:
        // o ci sono tutti o non ce n'è nessuno, e così non possono divergere.
        behavior: Option<BehaviorSignals>,
    ) -> Option<serde_json::Value> {
        let ua = request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        let qs = request.query_string.as_deref().unwrap_or("");
        // Lookup ASN fallito = "non lo so", non "non è un datacenter".
        let is_dc = self
            .edge
            .ip_intel()
            .lookup_asn(request.client_ip)
            .map(|a| a.is_hosting);
        let severity_numeric = match score.level {
            sentinel_core::RiskLevel::Critical => 4,
            sentinel_core::RiskLevel::High => 3,
            sentinel_core::RiskLevel::Medium => 2,
            sentinel_core::RiskLevel::Low => 1,
            sentinel_core::RiskLevel::None => 0,
        };
        let threat_type = score
            .flags
            .first()
            .map(|f| format!("{f:?}"))
            .unwrap_or_else(|| format!("{:?}", score.level));
        let input = sentinel_neural::threat_features::ThreatFeatureInput {
            risk_score: score.total_score() as f32,
            // Manca un campo confidence esplicito su LayerRiskScore → proxy = total_score.
            confidence: score.total_score() as f32,
            hour_of_day: chrono::Timelike::hour(&request.timestamp) as u8,
            day_of_week: chrono::Datelike::weekday(&request.timestamp).num_days_from_monday() as u8,
            is_datacenter: is_dc,
            // ip_intel non espone ancora questi due segnali: non misurati, non "falsi".
            is_tor: None,
            is_proxy: None,
            path: &request.path,
            user_agent: ua,
            query: qs,
            severity_numeric,
            burst_score: behavior.map(|b| b.burst_score),
            inter_request_stddev: behavior.map(|b| b.inter_request_stddev),
            // L'anomalia esiste solo se il layer behavioral ha girato: ai fast-path
            // edge/neural behavioral_score è ancora 0 di default, cioè non calcolato.
            anomaly_score: behavior.map(|_| score.behavioral_score as f32),
            threat_type: &threat_type,
            detection_source: source,
            request_method: &request.method,
        };

        // Meta threat_classifier in SHADOW: se un modello è caricato, gira e LOGGA la
        // probabilità — NON altera la decisione (rollout sicuro; si promuove quando validato).
        //
        // 2026-08-04: il vettore è ora COMPLETO. Prima il metodo HTTP passava da un
        // LabelEncoder che sarebbe dovuto arrivare in un file sidecar mai esportato:
        // l'encoder a runtime restava vuoto, quindi quella feature valeva sempre 0 mentre
        // nel training pesava 0.20 — il modello girava su un input che non aveva mai visto
        // in addestramento. Con l'one-hot a dominio chiuso il vettore di inferenza è
        // identico per costruzione a quello di training.
        if self.threat_classifier.is_loaded() {
            let vec = sentinel_neural::threat_features::extract(&input);
            if let Some(probs) = self.threat_classifier.predict(&vec) {
                let threat_prob = probs.get(1).copied().unwrap_or(0.0);

                // Accordo col verdetto dei layer. Si confronta col LIVELLO DI RISCHIO e non
                // con l'azione finale perché l'azione dipende anche da safe-mode e whitelist:
                // il livello è ciò che i layer hanno effettivamente concluso sulla richiesta.
                let layers_flag = matches!(
                    score.level,
                    sentinel_core::RiskLevel::High | sentinel_core::RiskLevel::Critical
                );
                self.shadow_agreement.record(threat_prob, layers_flag);

                tracing::info!(
                    source,
                    threat_prob,
                    layers_flag,
                    shadow = self.threat_classifier.is_shadow_active(),
                    "threat_classifier shadow prediction (non-authoritative)"
                );
            }
        }

        serde_json::to_value(sentinel_neural::threat_features::to_raw_record(&input)).ok()
    }

    /// Process a request through all 4 layers (v2.0.0)
    ///
    /// Pipeline: Edge (< 1ms) → Neural (< 5ms) → Behavioral (< 10ms) → Response
    /// Fast paths: Critical at edge, High at neural (skip deeper layers)
    /// v2.0.0 additions: JA3 correlation, identity graph scoring, intent chain detection
    pub async fn process(
        &self,
        request: &sentinel_core::Request,
        agent_id: Option<&sentinel_core::AgentId>,
    ) -> Result<Decision, SentinelError> {
        let start = std::time::Instant::now();
        let counter = self.request_counter.fetch_add(1, Ordering::Relaxed);

        // Periodic maintenance (every 1000 requests or 60s)
        if counter % 1000 == 0 {
            self.periodic_maintenance();
        }

        // WI-3b: Check micro-cache (IP + UA hash)
        let ua = request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        let cache_key = CacheKey {
            ip: request.client_ip,
            ua_hash: hash_ua(ua),
        };

        let ttl = if self.edge.ddos_detector().is_defense_mode_active() {
            CACHE_TTL_DEFENSE // 15s in defense mode
        } else {
            CACHE_TTL // 5s normal
        };

        if let Some(cached) = self.analysis_cache.get(&cache_key) {
            if cached.created_at.elapsed() < ttl {
                let action = cached.action.clone();
                let risk = cached.risk;
                drop(cached); // rilascia il ref DashMap prima di registrare la metrica
                // Conta ANCHE le decisioni servite dalla cache (entro TTL): un attacco
                // sostenuto dallo stesso (ip,ua) viene bloccato via cache-hit → senza
                // questo conteggio sarebbe INVISIBILE su /metrics. `record` usa solo
                // level + action → score minimo col solo level cached.
                metrics::record_request(
                    start.elapsed(),
                    &sentinel_core::LayerRiskScore { level: risk, ..Default::default() },
                    &action,
                );
                return Ok(Decision { action, risk });
            }
        }

        // WI-6: Periodically check for threat classifier model updates (every 60s)
        self.threat_classifier.check_for_updates();
        // Flywheel Fase 5: idem per il guardiano NEURALE (prompt-injection). Il cron di
        // retrain ripubblica prompt-injection.onnx → hot-reload senza riavviare Sentinel.
        self.neural.check_prompt_injection_updates();

        // ── Layer 1: Edge Shield (< 1ms) ──────────────────────────────────
        let edge_score = self.edge.analyze(request).await?;

        // v2.0.0: JA3 TLS fingerprinting (B1 + A10 — OPTIONAL, graceful if absent)
        let ja3_result = analyze_ja3(&request.headers);
        let mut ja3_risk_boost: f64 = 0.0;
        let mut ja3_flags: Vec<sentinel_core::RiskFlag> = Vec::new();

        // Only process JA3 if the hash was actually present (NotAvailable = header absent)
        if ja3_result.classification != Ja3Classification::NotAvailable {
            // JA3 risk contribution
            ja3_risk_boost += ja3_result.risk_contribution;

            // JA3-UA mismatch is a KILLER signal (+0.80)
            if ja3_result.ua_mismatch {
                ja3_risk_boost += ja3_result.ua_mismatch_risk;
                ja3_flags.push(sentinel_core::RiskFlag::Ja3Mismatch);
            }

            match ja3_result.classification {
                Ja3Classification::KnownScanner => {
                    ja3_flags.push(sentinel_core::RiskFlag::Ja3Scanner);
                }
                Ja3Classification::Unknown => {
                    ja3_flags.push(sentinel_core::RiskFlag::Ja3Unknown);
                }
                _ => {}
            }
        }

        // Fast path: Critical threats blocked immediately (edge alone)
        if edge_score.level == sentinel_core::RiskLevel::Critical {
            // fast-path edge: behavior non ancora girato → timing 0.0 (onesto).
            // fast-path edge: il layer behavioral non gira → nessun segnale suo.
            let mlf = self.build_ml_features(request, &edge_score, "edge", None);
            let action = self.maybe_safe_mode(
                &edge_score,
                || self.response.determine_action(request, &edge_score, agent_id, mlf.clone()),
                ProtectionLayer::Edge,
            ).await?;

            tracing::warn!(
                latency_us = start.elapsed().as_micros(),
                level = "edge",
                risk = ?edge_score.level,
                flags = ?edge_score.flags,
                "Request blocked at edge"
            );

            self.cache_and_record(cache_key, &action, start, &edge_score);
            return Ok(Decision { action, risk: edge_score.level });
        }

        // ── Layer 2: Neural Defense (< 5ms) ───────────────────────────────
        let neural_score = self.neural.analyze(request).await?;

        // Combine edge + neural + JA3
        let mut combined_score = edge_score.clone();
        combined_score.neural_score = neural_score.neural_score;
        combined_score.flags.extend(neural_score.flags);

        // Apply JA3 to edge score (it's an edge-layer signal integrated post-analysis)
        if ja3_risk_boost > 0.0 {
            combined_score.edge_score = (combined_score.edge_score + ja3_risk_boost).min(1.0);
        }
        combined_score.flags.extend(ja3_flags);

        // Update level based on combined score
        combined_score.update_level();

        // Fast path: High threats challenged (edge + neural)
        if combined_score.level >= sentinel_core::RiskLevel::High {
            // fast-path neural: behavior non ancora girato → timing 0.0 (onesto).
            // fast-path neural: idem, il behavioral è saltato.
            let mlf = self.build_ml_features(request, &combined_score, "neural", None);
            let action = self.maybe_safe_mode(
                &combined_score,
                || self.response.determine_action(request, &combined_score, agent_id, mlf.clone()),
                ProtectionLayer::Neural,
            ).await?;

            tracing::warn!(
                latency_us = start.elapsed().as_micros(),
                level = "neural",
                edge_score = combined_score.edge_score,
                neural_score = combined_score.neural_score,
                risk = ?combined_score.level,
                flags = ?combined_score.flags,
                "Request flagged by neural defense"
            );

            self.cache_and_record(cache_key, &action, start, &combined_score);
            return Ok(Decision { action, risk: combined_score.level });
        }

        // ── Layer 3: Behavioral Analysis (< 10ms) ─────────────────────────
        // v2.0.0: Now includes cross-IP correlation, identity graph,
        // intent detection, and timing fingerprint (all integrated in BehavioralAnalysis)
        let behavior_score = self.behavior.analyze(request, agent_id).await?;

        // Combine all layer scores
        combined_score.behavioral_score = behavior_score.behavioral_score;
        combined_score.flags.extend(behavior_score.flags);
        combined_score.update_level();

        // Record for learning (sampling-aware per A7)
        self.behavior.record(request, agent_id).await?;

        // Record risk score in behavioral memory for future pre-scoring
        self.behavior.record_risk(
            request.client_ip,
            combined_score.total_score(),
            &request.path,
        );

        // ── Layer 4: Response determination ────────────────────────────────
        // Timing REALI dal layer behavior (#5): burst (req/ultimo sec) + stddev inter-arrivo.
        // Disponibili qui perché behavior.analyze/record sono già girati (full-path).
        let (burst_f, stddev_f) = self.behavior.timing_features(request.client_ip);
        let behavior_signals = Some(BehaviorSignals {
            burst_score: burst_f,
            inter_request_stddev: stddev_f,
        });
        let mlf = self.build_ml_features(request, &combined_score, "behavioral", behavior_signals);
        let action = self.maybe_safe_mode(
            &combined_score,
            || self.response.determine_action(request, &combined_score, agent_id, mlf.clone()),
            ProtectionLayer::Behavioral,
        ).await?;

        let latency = start.elapsed();

        // Structured log with full v2.0.0 breakdown (N3: explainability)
        tracing::info!(
            latency_us = latency.as_micros(),
            edge_score = combined_score.edge_score,
            neural_score = combined_score.neural_score,
            behavior_score = combined_score.behavioral_score,
            total_score = combined_score.total_score(),
            risk = ?combined_score.level,
            action = ?action,
            flag_count = combined_score.flags.len(),
            ja3_available = ja3_result.hash.is_some(),
            ja3_mismatch = ja3_result.ua_mismatch,
            "Request processed (v2.0.0)"
        );

        // Benign sampling: 1 ogni N richieste PULITE (Allow) → classe NEGATIVA del training
        // del threat_classifier. Senza negativi il dataset è mono-classe = non addestrabile.
        // Sampling deterministico via counter (no RNG). Fire-and-forget. Lo skip (modello
        // non ancora utile) NON è un problema: alimenta solo il dataset, non la decisione.
        //
        // ⚠️ Il contatore è DEDICATO ai candidati: avanza solo qui, dove la richiesta è già
        // pulita E ha attraversato il full-path. Col contatore globale servivano due
        // coincidenze per produrre un campione, e la classe negativa cresceva ~25 volte più
        // lenta del previsto (51 campioni in un mese invece di ~60).
        let benign_candidate = matches!(action, sentinel_core::Action::Allow);
        if benign_candidate
            && self.benign_counter.fetch_add(1, Ordering::Relaxed) % BENIGN_SAMPLE_EVERY == 0
        {
            if let Some(mlf) = self.build_ml_features(request, &combined_score, "benign_sample", behavior_signals) {
                self.response.record_benign_sample(mlf);
            }
        }

        // Metriche + cache: record_request è ora DENTRO cache_and_record → copre questo
        // full-path E i fast-path block (edge/neural) che prima non venivano contati.
        self.cache_and_record(cache_key, &action, start, &combined_score);

        Ok(Decision { action, risk: combined_score.level })
    }

    /// Cache an analysis result and evict stale entries if needed
    fn cache_and_record(
        &self,
        cache_key: CacheKey,
        action: &sentinel_core::Action,
        start: Instant,
        score: &sentinel_core::LayerRiskScore,
    ) {
        // Metrica su OGNI decisione che passa di qui — inclusi i fast-path block (edge
        // Critical / neural High). Pre-fix `record_request` era SOLO sul full-path → un
        // DDoS bloccato all'edge era INVISIBILE su /metrics (mentre /sla lo contava).
        metrics::record_request(start.elapsed(), score, action);
        self.analysis_cache.insert(cache_key, CachedResult {
            action: action.clone(),
            risk: score.level,
            created_at: Instant::now(),
        });
        if self.analysis_cache.len() > MAX_CACHE_SIZE {
            self.evict_cache();
        }
    }

    /// G21.2: Safe mode PER-LAYER — se IL layer che ha deciso il blocco è
    /// sospeso, logga l'azione che AVREBBE preso ma lascia passare. Gli altri
    /// layer non sono toccati. Hard-WAF (pattern deterministici nel neural)
    /// blocca comunque a monte e non passa di qui.
    async fn maybe_safe_mode<F, Fut>(
        &self,
        score: &sentinel_core::LayerRiskScore,
        action_fn: F,
        layer: ProtectionLayer,
    ) -> Result<sentinel_core::Action, SentinelError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<sentinel_core::Action, SentinelError>>,
    {
        let action = action_fn().await?;

        if self.safe_mode.is_suspended(layer) {
            // Layer sospeso: logga la decisione soppressa, ma lascia passare.
            if !matches!(action, sentinel_core::Action::Allow) {
                tracing::warn!(
                    "[SAFE_MODE layer={}] blocking di questo layer sospeso (hard-WAF resta attiva) — \
                     score={:.2} decision=would_{:?} \
                     breakdown=edge:{:.2}|neural:{:.2}|behavior:{:.2}|total:{:.2}",
                    layer.as_str(),
                    score.total_score(),
                    action,
                    score.edge_score,
                    score.neural_score,
                    score.behavioral_score,
                    score.total_score(),
                );
            }
            return Ok(sentinel_core::Action::Allow);
        }

        Ok(action)
    }

    /// Periodic maintenance: cleanup behavioral data, check memory pressure
    fn periodic_maintenance(&self) {
        let mut last = self.last_cleanup.lock();
        if last.elapsed() >= CLEANUP_INTERVAL {
            *last = Instant::now();
            // Cleanup behavioral data (cross-IP, identity graph, intent, timing)
            self.behavior.cleanup();
            // Evict stale cache entries
            self.evict_cache();

            tracing::debug!(
                cache_size = self.analysis_cache.len(),
                "Periodic maintenance completed"
            );
        }
    }

    /// Verify a challenge response
    pub async fn verify_challenge(
        &self,
        challenge_id: &str,
        response: &str,
    ) -> Result<bool, SentinelError> {
        self.response.verify_challenge(challenge_id, response).await
    }

    /// Get health status (v2.0.0: includes identity graph + safe mode)
    pub fn health(&self) -> HealthStatus {
        HealthStatus {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            edge_ready: true,
            neural_ready: true,
            behavior_ready: true,
            response_ready: true,
            threat_classifier_loaded: self.threat_classifier.is_loaded(),
            threat_classifier_model: self.threat_classifier.current_model_path(),
            threat_classifier_shadow_active: self.threat_classifier.is_shadow_active(),
            threat_classifier_agreement: self.shadow_agreement.snapshot(),
            safe_mode_active: self.safe_mode.any_suspended(),
            safe_mode_suspended_layers: self.safe_mode.suspended_layers()
                .into_iter().map(|s| s.to_string()).collect(),
            identity_graph_size: self.behavior.identity_graph().tracked_identities(),
        }
    }

    /// Get statistics (v2.0.0: includes behavioral module stats)
    pub fn stats(&self) -> Stats {
        let response_stats = self.response.get_stats();

        Stats {
            active_bans: response_stats.active_bans,
            pending_challenges: response_stats.pending_challenges,
            escalations_today: response_stats.escalations_today,
            analysis_cache_size: self.analysis_cache.len(),
            identity_graph_size: self.behavior.identity_graph().tracked_identities(),
            total_requests: self.request_counter.load(Ordering::Relaxed),
            defense_mode_active: self.is_defense_mode_active(),
        }
    }

    /// Get defense mode status (WI-11)
    pub fn defense_status(&self) -> sentinel_edge::ddos::DefenseModeStatus {
        self.edge.ddos_detector().defense_status()
    }

    /// Check if defense mode is active (for fast-path decisions)
    pub fn is_defense_mode_active(&self) -> bool {
        self.edge.ddos_detector().is_defense_mode_active()
    }

    /// N5/compat: Enable safe mode su TUTTI i layer (blocking soft disabilitato,
    /// logging continua, hard-WAF resta attiva).
    pub fn enable_safe_mode(&self) {
        self.safe_mode.suspend_all();
        tracing::warn!("[SAFE_MODE] Enabled (all layers) — blocking disabled except hard WAF patterns");
    }

    /// N5/compat: Disable safe mode su TUTTI i layer (blocking riabilitato).
    pub fn disable_safe_mode(&self) {
        self.safe_mode.resume_all();
        tracing::warn!("[SAFE_MODE] Disabled (all layers) — full blocking re-enabled");
    }

    /// N5/compat: True se ALMENO un layer è in safe-mode.
    pub fn is_safe_mode_active(&self) -> bool {
        self.safe_mode.any_suspended()
    }

    /// G21.2: sospende il blocking di UN solo layer (gli altri restano attivi).
    /// Ritorna `true` se è stata una transizione attivo→sospeso.
    pub fn suspend_layer(&self, layer: ProtectionLayer) -> bool {
        let transitioned = self.safe_mode.suspend(layer);
        if transitioned {
            tracing::warn!(layer = layer.as_str(), "[SAFE_MODE] layer sospeso — solo questo layer in log-only");
        }
        transitioned
    }

    /// G21.2: riattiva il blocking di UN solo layer.
    pub fn resume_layer(&self, layer: ProtectionLayer) -> bool {
        let transitioned = self.safe_mode.resume(layer);
        if transitioned {
            tracing::warn!(layer = layer.as_str(), "[SAFE_MODE] layer riattivato — blocking ripristinato");
        }
        transitioned
    }

    /// G21.2: True se lo specifico layer è sospeso.
    pub fn is_layer_suspended(&self, layer: ProtectionLayer) -> bool {
        self.safe_mode.is_suspended(layer)
    }

    /// G21.2: elenco dei layer attualmente sospesi (per status/health/log).
    pub fn suspended_layers(&self) -> Vec<&'static str> {
        self.safe_mode.suspended_layers()
    }

    /// Evict expired entries from the analysis cache
    fn evict_cache(&self) {
        let ttl = if self.edge.ddos_detector().is_defense_mode_active() {
            CACHE_TTL_DEFENSE
        } else {
            CACHE_TTL
        };
        self.analysis_cache.retain(|_, cached| cached.created_at.elapsed() < ttl);
    }

    /// Number of cached analysis results
    pub fn cache_size(&self) -> usize {
        self.analysis_cache.len()
    }

    /// Get edge shield
    pub fn edge(&self) -> &EdgeShield {
        &self.edge
    }

    /// Get neural defense
    pub fn neural(&self) -> &NeuralDefense {
        &self.neural
    }

    /// Analyze LLM output content for safety (exposed for /analyze/content endpoint)
    pub async fn analyze_content(&self, content: &str) -> Result<ContentAnalysisResult, SentinelError> {
        let mut patterns: Vec<DetectedPattern> = Vec::new();
        let mut max_score: f64 = 0.0;
        let mut model_used = "none";

        // 1. LLM output safety (regex + optional ONNX)
        let safety = self.neural.llm_output_safety().analyze(content).await?;
        if safety.is_malicious {
            max_score = max_score.max(safety.score);
            model_used = safety.model_used;
            patterns.push(DetectedPattern {
                pattern_id: safety.pattern.clone().unwrap_or_else(|| "llm-output-safety".to_string()),
                category: "llm_output_safety".to_string(),
                severity: "critical".to_string(),
                matched_text: safety.pattern,
            });
        }

        // 2. Toxicity analysis
        let toxicity = self.neural.toxicity().analyze(content).await?;
        if toxicity.is_toxic {
            max_score = max_score.max(toxicity.score);
            if model_used == "none" {
                model_used = "toxicity";
            }
            let categories: Vec<String> = toxicity.categories.iter()
                .map(|c| format!("{:?}", c))
                .collect();
            patterns.push(DetectedPattern {
                pattern_id: format!("toxicity:{}", categories.join(",")),
                category: "toxicity".to_string(),
                severity: if toxicity.score >= 0.9 { "critical" } else { "high" }.to_string(),
                matched_text: None,
            });
        }

        let recommendation = if !patterns.is_empty() && max_score >= 0.8 {
            "redact"
        } else if !patterns.is_empty() {
            "flag"
        } else {
            "allow"
        };

        Ok(ContentAnalysisResult {
            is_malicious: !patterns.is_empty(),
            score: max_score,
            model_used: model_used.to_string(),
            patterns,
            recommendation: recommendation.to_string(),
        })
    }

    /// Get behavioral analysis
    pub fn behavior(&self) -> &BehavioralAnalysis {
        &self.behavior
    }

    /// Get response layer
    pub fn response(&self) -> &ResponseLayer {
        &self.response
    }

    /// Get threat classifier (for status reporting)
    pub fn threat_classifier(&self) -> &HotReloadableModel {
        &self.threat_classifier
    }
}

/// Content analysis result (for /analyze/content endpoint)
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentAnalysisResult {
    pub is_malicious: bool,
    pub score: f64,
    pub model_used: String,
    pub patterns: Vec<DetectedPattern>,
    pub recommendation: String,
}

/// Detected pattern in content analysis
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectedPattern {
    pub pattern_id: String,
    pub category: String,
    pub severity: String,
    pub matched_text: Option<String>,
}

/// Health status (v2.0.0)
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub edge_ready: bool,
    pub neural_ready: bool,
    pub behavior_ready: bool,
    pub response_ready: bool,
    pub threat_classifier_loaded: bool,
    pub threat_classifier_model: Option<String>,
    pub threat_classifier_shadow_active: bool,
    /// Accordo col verdetto dei layer: i numeri su cui decidere se dare peso al modello.
    /// Guardare `flag_rate_on_allowed` — quanto traffico oggi consentito verrebbe bloccato.
    pub threat_classifier_agreement: ShadowAgreementStats,
    /// v2.0.0: Whether safe mode is active (N5) — compat: true se ALMENO un layer sospeso.
    pub safe_mode_active: bool,
    /// G21.2: quali layer sono sospesi (vuoto = full blocking). Es. `["behavioral"]`.
    pub safe_mode_suspended_layers: Vec<String>,
    /// v2.0.0: Number of tracked identities
    pub identity_graph_size: usize,
}

/// Statistics (v2.0.0: enhanced)
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub active_bans: usize,
    pub pending_challenges: usize,
    pub escalations_today: usize,
    /// v2.0.0: Analysis cache entries
    pub analysis_cache_size: usize,
    /// v2.0.0: Identity graph tracked entities
    pub identity_graph_size: usize,
    /// v2.0.0: Total requests processed since boot
    pub total_requests: u64,
    /// v2.0.0: DDoS defense mode active
    pub defense_mode_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Criterio di promozione del meta threat_classifier ────────────────────────
    // Prima esisteva solo il commento «si promuove quando validato», senza che
    // "validato" significasse nulla di verificabile e senza che nessuno misurasse
    // alcunché. Questi test rendono il criterio una condizione con dei numeri.

    fn agreement(total: u64, flags_allowed: u64, agree_threat: u64) -> ShadowAgreementStats {
        let a = ShadowAgreement::default();
        a.total.store(total, Ordering::Relaxed);
        a.model_flags_allowed.store(flags_allowed, Ordering::Relaxed);
        a.agree_threat.store(agree_threat, Ordering::Relaxed);
        a.snapshot()
    }

    #[test]
    fn promozione_negata_senza_osservazioni_sufficienti() {
        let s = agreement(10, 0, 5);
        assert!(!s.promotion_ready);
        assert!(s.promotion_reason.contains("osservazioni insufficienti"), "{}", s.promotion_reason);
    }

    #[test]
    fn promozione_negata_se_bloccherebbe_traffico_consentito() {
        // 🔒 Il vincolo che conta: 5% del traffico oggi consentito verrebbe segnalato.
        // Sono clienti veri. Nessuna metrica di accuratezza può compensarlo.
        let s = agreement(10_000, 500, 400);
        assert!(!s.promotion_ready);
        assert!(s.promotion_reason.contains("clienti veri"), "{}", s.promotion_reason);
    }

    #[test]
    fn promozione_negata_se_non_ha_mai_riconosciuto_una_minaccia() {
        // Un modello che dice sempre "pulito" non disturba nessuno ed è inutile:
        // passerebbe il vincolo sui falsi positivi senza aver dimostrato niente.
        let s = agreement(10_000, 0, 0);
        assert!(!s.promotion_ready);
        assert!(s.promotion_reason.contains("non ha mai concordato"), "{}", s.promotion_reason);
    }

    #[test]
    fn promozione_concessa_solo_con_tutte_le_condizioni() {
        let s = agreement(10_000, 50, 120); // 0.5% sul consentito, minacce riconosciute
        assert!(s.promotion_ready, "{}", s.promotion_reason);
        assert!(s.promotion_reason.contains("10000 osservazioni"), "{}", s.promotion_reason);
    }

    #[test]
    fn promozione_al_confine_esatto_della_soglia_falsi_positivi() {
        // Esattamente all'1%: ammesso (il vincolo è `>`), un capello sopra: negato.
        let ok = agreement(10_000, 100, 10);
        assert!(ok.promotion_ready, "{}", ok.promotion_reason);
        let ko = agreement(10_000, 101, 10);
        assert!(!ko.promotion_ready, "{}", ko.promotion_reason);
    }

    #[test]
    fn accordo_classifica_i_quattro_quadranti() {
        let a = ShadowAgreement::default();
        a.record(0.9, true);   // modello: minaccia — layer: bloccato
        a.record(0.1, false);  // modello: pulito  — layer: passato
        a.record(0.9, false);  // ⚠️ modello: minaccia — layer: PASSATO (falso positivo)
        a.record(0.1, true);   // modello: pulito  — layer: bloccato
        let s = a.snapshot();
        assert_eq!(s.total, 4);
        assert_eq!(s.agree_threat, 1);
        assert_eq!(s.agree_clean, 1);
        assert_eq!(s.model_flags_allowed, 1);
        assert_eq!(s.model_misses_blocked, 1);
        assert!((s.flag_rate_on_allowed - 0.25).abs() < 1e-9);
    }

    #[test]
    fn accordo_senza_dati_non_divide_per_zero() {
        let s = ShadowAgreement::default().snapshot();
        assert_eq!(s.total, 0);
        assert_eq!(s.flag_rate_on_allowed, 0.0);
        assert!(!s.promotion_ready);
    }

    #[tokio::test]
    async fn test_sentinel_creation() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config);
        assert!(sentinel.is_ok());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        let health = sentinel.health();
        assert_eq!(health.status, "healthy");
        assert!(!health.safe_mode_active);
        assert!(health.safe_mode_suspended_layers.is_empty());
        assert_eq!(health.identity_graph_size, 0);
    }

    // ── G21.2: safe-mode PER-LAYER ──────────────────────────────────────

    #[test]
    fn protection_layer_parse_roundtrip_and_aliases() {
        for l in ProtectionLayer::ALL {
            assert_eq!(ProtectionLayer::parse(l.as_str()), Some(l), "roundtrip {l:?}");
            // case-insensitive
            assert_eq!(ProtectionLayer::parse(&l.as_str().to_uppercase()), Some(l));
        }
        // alias storico "full" → behavioral (era il nome del layer 3 nei log)
        assert_eq!(ProtectionLayer::parse("full"), Some(ProtectionLayer::Behavioral));
        assert_eq!(ProtectionLayer::parse("behavior"), Some(ProtectionLayer::Behavioral));
        assert_eq!(ProtectionLayer::parse("nonexistent"), None);
        assert_eq!(ProtectionLayer::parse(""), None);
    }

    #[test]
    fn safe_mode_registry_suspends_one_layer_in_isolation() {
        let reg = SafeModeRegistry::new(false);
        assert!(!reg.any_suspended());

        // Sospendi SOLO behavioral → edge e neural restano attivi.
        assert!(reg.suspend(ProtectionLayer::Behavioral), "prima sospensione = transizione");
        assert!(reg.is_suspended(ProtectionLayer::Behavioral));
        assert!(!reg.is_suspended(ProtectionLayer::Edge), "edge NON deve essere toccato");
        assert!(!reg.is_suspended(ProtectionLayer::Neural), "neural NON deve essere toccato");
        assert!(reg.any_suspended());
        assert_eq!(reg.suspended_layers(), vec!["behavioral"]);

        // Idempotenza: ri-sospendere NON è una transizione.
        assert!(!reg.suspend(ProtectionLayer::Behavioral), "ri-sospensione non è transizione");

        // Riattiva → torna pulito.
        assert!(reg.resume(ProtectionLayer::Behavioral), "resume = transizione");
        assert!(!reg.resume(ProtectionLayer::Behavioral), "doppio resume non è transizione");
        assert!(!reg.any_suspended());
    }

    #[test]
    fn safe_mode_registry_suspend_all_and_resume_all() {
        let reg = SafeModeRegistry::new(false);
        reg.suspend_all();
        for l in ProtectionLayer::ALL {
            assert!(reg.is_suspended(l), "{l:?} deve essere sospeso");
        }
        assert_eq!(reg.suspended_layers().len(), 3);
        reg.resume_all();
        assert!(!reg.any_suspended());
    }

    #[test]
    fn safe_mode_registry_boot_all_suspended() {
        // env SENTINEL_SAFE_MODE=true → boot con tutti i layer sospesi.
        let reg = SafeModeRegistry::new(true);
        assert!(reg.any_suspended());
        assert_eq!(reg.suspended_layers().len(), 3);
    }

    #[tokio::test]
    async fn test_clean_request() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        let request = sentinel_core::Request {
            path: "/api/posts".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let decision = sentinel.process(&request, None).await.unwrap();
        assert!(matches!(decision.action, sentinel_core::Action::Allow));
        // Una richiesta pulita non deve produrre rischio elevato.
        assert!(
            decision.risk < sentinel_core::RiskLevel::High,
            "clean request non deve essere High/Critical, era {:?}",
            decision.risk
        );
    }

    #[tokio::test]
    async fn risk_effettivo_propagato_su_richiesta_malevola() {
        // BUG-BOUNTY / regressione del placeholder `RiskKind::None`:
        // prima del fix `process` esponeva solo l'Action e lo SLA store
        // registrava SEMPRE risk None. Una SQLi UNION SELECT deve invece
        // produrre un risk NON-None nel Decision.
        let sentinel = Sentinel::new(SentinelConfig::default()).unwrap();
        let request = sentinel_core::Request {
            path: "/users?id=1 UNION SELECT password FROM users".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let decision = sentinel.process(&request, None).await.unwrap();

        assert_ne!(
            decision.risk,
            sentinel_core::RiskLevel::None,
            "una SQLi UNION SELECT deve produrre risk > None (era il placeholder fisso pre-fix)"
        );
        // Coerenza azione↔rischio: se la richiesta NON è semplicemente Allow,
        // il rischio dietro la decisione dev'essere almeno High.
        if !matches!(decision.action, sentinel_core::Action::Allow) {
            assert!(
                decision.risk >= sentinel_core::RiskLevel::High,
                "azione di contrasto {:?} con risk troppo basso {:?}",
                decision.action,
                decision.risk
            );
        }
    }

    #[tokio::test]
    async fn cache_hit_preserva_il_risk_effettivo() {
        // ANTI-REGRESSIONE del punto fragile del fix: un cache-hit (seconda
        // chiamata identica entro il TTL) DEVE ripropagare lo stesso risk
        // della prima analisi. Se la cache non lo conservasse, il secondo
        // Decision tornerebbe al default None mascherando l'attacco.
        let sentinel = Sentinel::new(SentinelConfig::default()).unwrap();
        let request = sentinel_core::Request {
            path: "/users?id=1 UNION SELECT password FROM users".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let first = sentinel.process(&request, None).await.unwrap();
        let second = sentinel.process(&request, None).await.unwrap(); // cache-hit

        assert_eq!(
            first.risk, second.risk,
            "il cache-hit deve preservare il risk: prima={:?} dopo={:?}",
            first.risk, second.risk
        );
        assert_ne!(
            second.risk,
            sentinel_core::RiskLevel::None,
            "il cache-hit non deve azzerare il risk a None"
        );
    }

    #[tokio::test]
    async fn test_safe_mode() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        assert!(!sentinel.is_safe_mode_active());
        sentinel.enable_safe_mode();
        assert!(sentinel.is_safe_mode_active());

        // In safe mode, all requests should be allowed
        let request = sentinel_core::Request {
            path: "/api/posts".to_string(),
            method: "GET".to_string(),
            ..Default::default()
        };

        let decision = sentinel.process(&request, None).await.unwrap();
        assert!(matches!(decision.action, sentinel_core::Action::Allow));

        sentinel.disable_safe_mode();
        assert!(!sentinel.is_safe_mode_active());
    }

    #[tokio::test]
    async fn safe_mode_per_layer_via_sentinel_api() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        // Sospendi solo Edge: gli altri layer NON devono risultare sospesi.
        assert!(sentinel.suspend_layer(ProtectionLayer::Edge));
        assert!(sentinel.is_layer_suspended(ProtectionLayer::Edge));
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Neural));
        assert!(!sentinel.is_layer_suspended(ProtectionLayer::Behavioral));
        // compat: any_suspended true, ma NON è safe-mode globale.
        assert!(sentinel.is_safe_mode_active());
        assert_eq!(sentinel.suspended_layers(), vec!["edge"]);
        assert_eq!(sentinel.health().safe_mode_suspended_layers, vec!["edge".to_string()]);

        // Riattiva solo Edge → full blocking ripristinato.
        assert!(sentinel.resume_layer(ProtectionLayer::Edge));
        assert!(!sentinel.is_safe_mode_active());
        assert!(sentinel.health().safe_mode_suspended_layers.is_empty());
    }

    #[tokio::test]
    async fn test_stats_v2() {
        let config = SentinelConfig::default();
        let sentinel = Sentinel::new(config).unwrap();

        let stats = sentinel.stats();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.analysis_cache_size, 0);
        assert_eq!(stats.identity_graph_size, 0);
        assert!(!stats.defense_mode_active);
    }
}
