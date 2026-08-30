//! SENTINEL Behavioral Analysis - Layer 3 (v2.0.0)
//!
//! Agent behavior profiling and anomaly detection:
//! - Per-agent behavioral baselines
//! - Anomaly detection (Isolation Forest)
//! - Coordinated attack detection (DBSCAN clustering)
//! - Session analysis (hijacking, fingerprint drift)
//! - Cross-IP behavioral graph (Sybil, distributed probe, coordinated timing)
//! - Risk memory layer (path criticality, IP/UA cumulative profiles)
//! - Session path modeling (navigation sequence analysis)
//! - Cross-IP correlator (coordinated, probing, botnet, slow-drip, slow-distributed)
//! - Identity graph (probabilistic multi-signal identity, NAT-safe, risk decay)
//! - Intent detection (path sequence → recognized attack intent)
//! - Timing fingerprint (WEAK signal — capped +0.20, never blocks alone, Section A17/C3)

pub mod agent_profile;
pub mod anomaly;
pub mod anomaly_baseline;
pub mod coordination;
pub mod cross_ip;
pub mod identity_graph;
pub mod intent;
pub mod session;
pub mod behavior_graph;
pub mod risk_memory;
pub mod session_path;
pub mod layer3_rules;
pub mod slow_enumeration;

pub use layer3_rules::{Layer3Rules, RuleDetection};

use sentinel_core::{AgentId, Request, LayerRiskScore as RiskScore, RiskLevel, RiskFlag, SentinelError, BehaviorConfig};
use std::sync::Arc;
use std::hash::{Hash, Hasher};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use dashmap::DashMap;
use sentinel_core::sharded_lru::ShardedLru;

pub use agent_profile::{AgentProfiler, AgentBehavior};
pub use anomaly::{AnomalyDetector, AnomalyType};
pub use coordination::{CoordinationDetector, CoordinatedAttack};
pub use session::{SessionAnalyzer, SessionRisk};
pub use behavior_graph::{BehaviorGraph, GraphDetection, GraphPattern};
pub use risk_memory::{RiskMemory, RiskMemoryResult, PathCriticality, classify_path};
pub use session_path::{SessionPathAnalyzer, SessionPathResult, SessionPathDetectionType};
pub use cross_ip::{CrossIpCorrelator, CrossIpDetection, CrossIpDetectionType};
pub use identity_graph::{IdentityGraph, IdentityId};
pub use intent::{IntentDetector, RecognizedIntent};
pub use slow_enumeration::{SlowEnumerationDetector, EnumCandidate};

/// Hash a string using DefaultHasher (for UA fingerprinting)
fn hash_string(s: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

// ─── Timing Fingerprint (Section C3 + A17 — WEAK signal) ────────────────────

/// Maximum timing contribution (A17: CAPPED at +0.20, NEVER blocks alone)
const TIMING_MAX_CONTRIBUTION: f64 = 0.20;
/// Minimum requests before timing analysis is meaningful
const TIMING_MIN_REQUESTS: usize = 3;
/// Maximum timing intervals to store per IP
const TIMING_MAX_INTERVALS: usize = 30;

/// Timing fingerprint for a session/IP
struct TimingProfile {
    /// Inter-request intervals in milliseconds
    intervals: VecDeque<f64>,
    /// Last request timestamp
    last_request: Instant,
    /// Request count
    request_count: u64,
}

impl TimingProfile {
    fn new() -> Self {
        Self {
            intervals: VecDeque::with_capacity(TIMING_MAX_INTERVALS),
            last_request: Instant::now(),
            request_count: 0,
        }
    }

    /// Record a new request and return the inter-request interval in ms
    fn record(&mut self) -> Option<f64> {
        let now = Instant::now();
        self.request_count += 1;
        let interval_ms = now.duration_since(self.last_request).as_secs_f64() * 1000.0;
        self.last_request = now;

        if self.request_count > 1 {
            if self.intervals.len() >= TIMING_MAX_INTERVALS {
                self.intervals.pop_front();
            }
            self.intervals.push_back(interval_ms);
            Some(interval_ms)
        } else {
            None
        }
    }

    /// Calculate coefficient of variation (stddev / mean)
    /// CV < 0.1 = too regular → bot (+0.15, CAPPED by A17)
    fn coefficient_of_variation(&self) -> Option<f64> {
        if self.intervals.len() < TIMING_MIN_REQUESTS {
            return None;
        }

        let n = self.intervals.len() as f64;
        let mean: f64 = self.intervals.iter().sum::<f64>() / n;
        if mean <= 0.0 {
            return None;
        }

        let variance: f64 = self.intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();
        Some(stddev / mean)
    }

    /// Mean inter-request interval in milliseconds
    fn mean_interval_ms(&self) -> Option<f64> {
        if self.intervals.len() < TIMING_MIN_REQUESTS {
            return None;
        }
        let n = self.intervals.len() as f64;
        Some(self.intervals.iter().sum::<f64>() / n)
    }

    /// Analyze timing and return a risk contribution (CAPPED at TIMING_MAX_CONTRIBUTION)
    /// Returns (risk_contribution, is_timing_only_signal)
    fn analyze(&self) -> (f64, bool) {
        let cv = match self.coefficient_of_variation() {
            Some(cv) => cv,
            None => return (0.0, false),
        };
        let mean = self.mean_interval_ms().unwrap_or(1000.0);

        let mut risk: f64 = 0.0;

        // CV < 0.1 = too regular → bot signal (+0.15, CAPPED)
        if cv < 0.1 {
            risk += 0.15;
        }

        // Mean < 200ms = superhuman speed → bot signal (+0.20, CAPPED)
        if mean < 200.0 {
            risk += 0.20;
        }

        // Cap at TIMING_MAX_CONTRIBUTION (A17)
        let capped = risk.min(TIMING_MAX_CONTRIBUTION);
        (capped, true)
    }
}

// ─── Session Memory Bounded (Section A7) ─────────────────────────────────────

/// Maximum sessions tracked (A7: cap 5000 sessions)
const MAX_SESSIONS: usize = 5000;
/// Sample rate when approaching capacity (A7: > 4000 → 50% sample)
const SESSION_SAMPLE_THRESHOLD_50: usize = 4000;
/// Sample rate when near capacity (A7: > 4500 → 20% sample)
const SESSION_SAMPLE_THRESHOLD_20: usize = 4500;

/// Behavioral Analysis Layer (v2.0.0)
pub struct BehavioralAnalysis {
    config: BehaviorConfig,
    profiler: Arc<AgentProfiler>,
    anomaly_detector: Arc<AnomalyDetector>,
    coordination_detector: Arc<CoordinationDetector>,
    session_analyzer: Arc<SessionAnalyzer>,
    behavior_graph: Arc<BehaviorGraph>,
    risk_memory: Arc<RiskMemory>,
    session_path_analyzer: Arc<SessionPathAnalyzer>,
    /// v2.0.0: Cross-IP correlator (B3)
    cross_ip_correlator: Arc<CrossIpCorrelator>,
    /// v2.0.0: Identity graph (C1)
    identity_graph: Arc<IdentityGraph>,
    /// v2.0.0: Intent detector (C2)
    intent_detector: Arc<IntentDetector>,
    /// v2.0.0: Timing profiles per IP (C3 + A17 — WEAK). `ShardedLru`: IP-keyed → bound
    /// HARD realtime (evict LRU O(1)). Pre-fix: DashMap con cap soft + batch-evict O(n) sort.
    timing_profiles: ShardedLru<IpAddr, TimingProfile>,
    /// v2.0.0: Atomic request counter for sampling (A7)
    request_counter: AtomicU64,
    /// F4 (2026-06-02): Layer 3 deterministic behavioral rules with sliding windows
    /// Rules 1-5: 4xx burst, multi-UA churn, fake-referer, path-traversal seq, cross-IP bridge
    layer3: Arc<Layer3Rules>,
    /// F6 (2026-06-02): JSONL emitter for LoRA-ready behavioral events
    /// Each detection becomes a narrative event with human description + decision label
    pub event_log: Arc<DashMap<u64, RuleDetection>>,
    /// Slow-enumeration detector (2026-06-20): VARIETÀ di path in errore-di-probing
    /// (401/403/404) per IP in finestra larga — chi mappa la struttura reale sotto-rate.
    /// Alimentato dal feedback /response/observed; shadow-mode (non contribuisce al ban).
    slow_enum: Arc<SlowEnumerationDetector>,
}

impl BehavioralAnalysis {
    /// Create new behavioral analysis layer
    pub fn new(config: BehaviorConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            profiler: Arc::new(AgentProfiler::new(&config)?),
            anomaly_detector: Arc::new(AnomalyDetector::new(&config)?),
            coordination_detector: Arc::new(CoordinationDetector::new(&config)?),
            session_analyzer: Arc::new(SessionAnalyzer::new(&config)?),
            behavior_graph: Arc::new(BehaviorGraph::new()),
            risk_memory: Arc::new(RiskMemory::new()),
            session_path_analyzer: Arc::new(SessionPathAnalyzer::new()),
            cross_ip_correlator: Arc::new(CrossIpCorrelator::new()),
            identity_graph: Arc::new(IdentityGraph::new()),
            intent_detector: Arc::new(IntentDetector::new()),
            timing_profiles: ShardedLru::new(MAX_SESSIONS),
            request_counter: AtomicU64::new(0),
            layer3: Arc::new(Layer3Rules::new()),
            event_log: Arc::new(DashMap::new()),
            slow_enum: Arc::new(SlowEnumerationDetector::new()),
            config,
        })
    }

    /// Registra una risposta osservata (ip, status, path) nel detector slow-enumeration.
    /// Conta SOLO gli status di probing (401/403/404). Ritorna `Some(EnumCandidate)` quando
    /// l'IP supera la soglia di path DISTINTI nella finestra. SHADOW: non banna, non tocca
    /// il behavioral_score — il chiamante (server) lo trasforma in un threat-record shadow.
    pub fn record_enumeration(&self, ip: IpAddr, status: u16, path: &str) -> Option<EnumCandidate> {
        self.slow_enum.record(ip, status, path)
    }

    /// Analyze request behavior (v2.0.0 — with cross-IP, identity, intent, timing)
    /// Target latency: < 10ms
    pub async fn analyze(
        &self,
        request: &Request,
        agent_id: Option<&AgentId>,
    ) -> Result<RiskScore, SentinelError> {
        let mut score = RiskScore::default();
        let ip = request.client_ip;
        let ua = request.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");

        // ── 0. Risk Memory pre-scoring (path criticality + IP history) ───
        let risk_mem = self.risk_memory.pre_score(ip, &request.path);

        // Apply IP risk from memory
        if risk_mem.ip_risk_points > 0 {
            score.behavioral_score += (risk_mem.ip_risk_points as f64) / 100.0;
        }

        // ── 1. Session analysis (always — includes honeypot history check) ──
        let session_risk = self.session_analyzer.analyze(request).await?;
        score.behavioral_score += session_risk.score * 0.3;

        if session_risk.is_suspicious {
            score.add_flag(RiskFlag::SuspiciousSession);
        }

        // Check for honeypot history (server-computed, never from client)
        if session_risk.reason.as_deref() == Some("IP has honeypot history (server-verified)") {
            score.add_flag(RiskFlag::HoneypotTriggered);
            // Honeypot = near-certain malicious — boost behavioral score significantly
            score.behavioral_score += 0.5;
        }

        // ── 2. Agent profiling (if authenticated) ────────────────────────
        if let Some(agent_id) = agent_id {
            let behavior = self.profiler.analyze(agent_id, request).await?;

            if behavior.is_anomalous {
                score.add_flag(RiskFlag::BehaviorAnomaly);
                score.behavioral_score += 0.4;
            }

            // Check velocity (too many requests too fast)
            if behavior.velocity_exceeded {
                score.add_flag(RiskFlag::VelocityExceeded);
                score.behavioral_score += 0.3;
            }

            // Check pattern deviation
            if behavior.pattern_deviation > self.config.deviation_threshold {
                score.add_flag(RiskFlag::PatternDeviation);
                score.behavioral_score += behavior.pattern_deviation * 0.5;
            }
        }

        // ── 3. Anomaly detection (ML-based) ──────────────────────────────
        if self.config.enable_ml_anomaly {
            let anomalies = self.anomaly_detector.detect(request).await?;
            for anomaly in &anomalies {
                match anomaly {
                    AnomalyType::StatisticalOutlier => {
                        score.add_flag(RiskFlag::StatisticalAnomaly);
                        score.behavioral_score += 0.3;
                    }
                    AnomalyType::TemporalAnomaly => {
                        score.add_flag(RiskFlag::TemporalAnomaly);
                        score.behavioral_score += 0.4;
                    }
                    AnomalyType::SequenceAnomaly => {
                        score.add_flag(RiskFlag::SequenceAnomaly);
                        score.behavioral_score += 0.5;
                    }
                }
            }
        }

        // ── 4. Coordinated attack detection ──────────────────────────────
        if self.config.enable_coordination_detection {
            if let Some(attack) = self.coordination_detector.detect(request).await? {
                match attack {
                    CoordinatedAttack::BotNet => {
                        score.add_flag(RiskFlag::CoordinatedBotnet);
                        score.behavioral_score += 0.9;
                    }
                    CoordinatedAttack::DistributedProbing => {
                        score.add_flag(RiskFlag::DistributedProbing);
                        score.behavioral_score += 0.7;
                    }
                    CoordinatedAttack::SybilAttack => {
                        score.add_flag(RiskFlag::SybilAttack);
                        score.behavioral_score += 0.8;
                    }
                }
            }
        }

        // ── 5. Cross-IP behavioral graph (only for IPs with some risk) ───
        if score.behavioral_score > 0.1 {
            let ua_hash = hash_string(ua);

            // Record in graph
            self.behavior_graph.record(ip, ua_hash, &request.path);

            // Detect patterns
            let graph_detections = self.behavior_graph.detect(ip, ua_hash);
            for detection in &graph_detections {
                match detection.pattern {
                    GraphPattern::Sybil => {
                        score.add_flag(RiskFlag::SybilAttack);
                        score.behavioral_score += 0.2;
                    }
                    GraphPattern::CoordinatedTiming => {
                        score.add_flag(RiskFlag::CoordinatedBotnet);
                        score.behavioral_score += 0.25;
                    }
                    GraphPattern::DistributedProbe => {
                        score.add_flag(RiskFlag::DistributedProbing);
                        score.behavioral_score += 0.15;
                    }
                }
            }
        }

        // ── 6. Session path analysis ─────────────────────────────────────
        let path_result = self.session_path_analyzer.analyze_and_record(
            ip,
            &request.path,
            &request.method,
        );
        if path_result.risk_points > 0 {
            score.behavioral_score += (path_result.risk_points as f64) / 100.0;

            // Add appropriate flags
            for detection in &path_result.detections {
                match detection.detection_type {
                    SessionPathDetectionType::ScannerSequence => {
                        score.add_flag(RiskFlag::Scanner);
                    }
                    SessionPathDetectionType::PathRepetition => {
                        score.add_flag(RiskFlag::AnomalousPattern);
                    }
                    SessionPathDetectionType::ApiOnly => {
                        score.add_flag(RiskFlag::AnomalousPattern);
                    }
                    SessionPathDetectionType::LowDiversity => {
                        score.add_flag(RiskFlag::BehaviorAnomaly);
                    }
                }
            }
        }

        // ── 7. v2.0.0: Cross-IP Correlation (B3) ────────────────────────
        {
            // Record the request in the correlator
            self.cross_ip_correlator.record(ip, &request.path, ua, None, None);

            // Detect cross-IP patterns
            let cross_ip_detections = self.cross_ip_correlator.detect(
                ip,
                &request.path,
                ua,
                None,   // ASN — will be enriched when JA3/ASN integration is done
                0.0,    // error rate — will be computed when we track per-IP error rates
            );

            for detection in &cross_ip_detections {
                score.behavioral_score += detection.risk_add;
                match detection.detection_type {
                    CrossIpDetectionType::Coordinated => {
                        score.add_flag(RiskFlag::CrossIpCoordinated);
                    }
                    CrossIpDetectionType::Probing => {
                        score.add_flag(RiskFlag::DistributedProbing);
                    }
                    CrossIpDetectionType::Botnet => {
                        score.add_flag(RiskFlag::CoordinatedBotnet);
                    }
                    CrossIpDetectionType::SlowDrip => {
                        score.add_flag(RiskFlag::CrossIpSlowDrip);
                    }
                    CrossIpDetectionType::SlowProbe => {
                        score.add_flag(RiskFlag::CrossIpSlowDrip);
                    }
                    CrossIpDetectionType::SlowDistributed => {
                        score.add_flag(RiskFlag::CrossIpSlowDistributed);
                    }
                }

                // F4 (2026-06-02): bridge automatico cross_ip → Rule 5 Layer 3.
                // Solo per pattern coordinati che meritano BAN (no SlowProbe singolo).
                let pattern_label = match detection.detection_type {
                    CrossIpDetectionType::Botnet => Some("botnet"),
                    CrossIpDetectionType::Coordinated => Some("coordinated_attack"),
                    CrossIpDetectionType::SlowDistributed => Some("slow_distributed_low_rate"),
                    _ => None, // Probing / SlowDrip / SlowProbe restano solo come signal score
                };
                if let Some(pattern) = pattern_label {
                    let layer3_detection = self.layer3.record_cross_ip_signature(
                        ip,
                        pattern,
                        detection.ip_count,
                    );
                    self.event_log.insert(layer3_detection.event_id, layer3_detection);
                }
            }
        }

        // ── 8. v2.0.0: Intent Detection (C2) ────────────────────────────
        {
            let intent_result = self.intent_detector.analyze(ip, &request.path, &request.method);

            for detected_intent in &intent_result.intents {
                score.behavioral_score += detected_intent.risk_add;
                match detected_intent.intent {
                    RecognizedIntent::Reconnaissance => {
                        score.add_flag(RiskFlag::IntentReconnaissance);
                    }
                    RecognizedIntent::CredentialStuffing => {
                        score.add_flag(RiskFlag::IntentCredentialStuffing);
                    }
                    RecognizedIntent::DataExfiltration => {
                        score.add_flag(RiskFlag::IntentDataExfiltration);
                    }
                    RecognizedIntent::VulnerabilityProbe => {
                        score.add_flag(RiskFlag::IntentVulnerabilityProbe);
                    }
                    RecognizedIntent::ApiEnumeration => {
                        score.add_flag(RiskFlag::IntentApiEnumeration);
                    }
                    RecognizedIntent::ContentScraping => {
                        score.add_flag(RiskFlag::IntentContentScraping);
                    }
                }
            }

            // Intent chain bonus (C2 fix — multiple intents in same session)
            if intent_result.chain_bonus > 0.0 {
                score.behavioral_score += intent_result.chain_bonus;
                score.add_flag(RiskFlag::IntentChainBonus);
            }
        }

        // ── 9. v2.0.0: Identity Graph (C1) ──────────────────────────────
        {
            let http_fingerprint = request.headers.get("accept")
                .map(|s| hash_string(s))
                .unwrap_or(0);
            let behavior_hash = hash_string(&request.path);
            let cookie_hash = request.headers.get("cookie")
                .map(|s| hash_string(s));

            let identity_result = self.identity_graph.process(
                ip,
                ua,
                http_fingerprint,
                behavior_hash,
                cookie_hash,
                score.behavioral_score,
            );

            if identity_result.is_tracked {
                score.add_flag(RiskFlag::IdentityTracked);
            }
            if identity_result.has_weak_association {
                score.add_flag(RiskFlag::WeakAssociation);
            }
            if identity_result.identity_churn_detected {
                score.add_flag(RiskFlag::IdentityChurn);
            }

            // Apply cumulative risk from identity (with decay)
            if identity_result.effective_risk > 0.0 {
                score.behavioral_score += identity_result.effective_risk * 0.3;
            }
        }

        // ── 10. v2.0.0: Timing Fingerprint (C3 + A17 — WEAK) ────────────
        // Sampling condizionale: only track if ≥ 3 requests OR already suspicious
        {
            let should_track_timing = self.timing_profiles.with_peek(&ip, |o| match o {
                Some(p) => p.request_count >= TIMING_MIN_REQUESTS as u64,
                None => score.behavioral_score > 0.3, // Only start tracking if already suspicious
            });

            if should_track_timing {
                let timing_risk =
                    self.timing_profiles.with_entry_mut(ip, TimingProfile::new, |profile| {
                        profile.record();
                        let (risk, _is_timing_signal) = profile.analyze();
                        risk
                    });
                if timing_risk > 0.0 {
                    // A17: timing NEVER blocks alone — it's corroborative only
                    // The flag below tells the decision engine this is a weak signal
                    score.add_flag(RiskFlag::TimingAnomaly);
                    score.behavioral_score += timing_risk;
                }
            } else {
                // Still record the request for future timing analysis
                self.timing_profiles
                    .with_entry_mut(ip, TimingProfile::new, |profile| profile.record());
            }
        }

        // ── 11. F4 (2026-06-02): Layer 3 deterministic behavioral rules ─
        // Rules 2, 3, 4 run on every request (rule 1 needs response, rule 5
        // is bridged from cross_ip_correlator detections above).
        {
            // Rule 2: multi-UA churn per IP (3+ distinct UA in 5min = bot rotation)
            if !ua.is_empty() {
                if let Some(detection) = self.layer3.record_ua(ip, ua) {
                    score.behavioral_score += detection.severity_score;
                    score.add_flag(RiskFlag::BehaviorAnomaly);
                    self.event_log.insert(detection.event_id, detection);
                }
            }

            // Rule 3: external referer to deep API/admin path (forgery probe)
            let referer = request.headers.get("referer").map(|s| s.as_str());
            // Origin = our domain (best-effort from Host header)
            let our_origin = request.headers.get("host").map(|s| s.as_str()).unwrap_or("");
            if let Some(detection) = self.layer3.record_referer(ip, referer, &request.path, our_origin) {
                score.behavioral_score += detection.severity_score;
                score.add_flag(RiskFlag::AnomalousPattern);
                self.event_log.insert(detection.event_id, detection);
            }

            // Rule 4: path-traversal sequence (5+ `../` in 60s)
            if let Some(detection) = self.layer3.record_path_traversal(ip, &request.path) {
                score.behavioral_score += detection.severity_score;
                score.add_flag(RiskFlag::Scanner);
                self.event_log.insert(detection.event_id, detection);
            }
        }

        // ── Normalize and classify ───────────────────────────────────────
        score.behavioral_score = score.behavioral_score.min(1.0);

        // Set risk level based on behavioral score
        score.level = if score.behavioral_score >= 0.8 {
            RiskLevel::Critical
        } else if score.behavioral_score >= 0.6 {
            RiskLevel::High
        } else if score.behavioral_score >= 0.4 {
            RiskLevel::Medium
        } else if score.behavioral_score >= 0.2 {
            RiskLevel::Low
        } else {
            RiskLevel::None
        };

        Ok(score)
    }

    /// Record a request for learning
    pub async fn record(&self, request: &Request, agent_id: Option<&AgentId>) -> Result<(), SentinelError> {
        // A7: Memory bounded session tracking — sampling when approaching capacity
        let counter = self.request_counter.fetch_add(1, Ordering::Relaxed);
        let session_count = self.session_analyzer.session_count();

        let should_record = if session_count >= SESSION_SAMPLE_THRESHOLD_20 {
            counter % 5 == 0 // 20% sample
        } else if session_count >= SESSION_SAMPLE_THRESHOLD_50 {
            counter % 2 == 0 // 50% sample
        } else {
            true // Full recording
        };

        if should_record {
            // Record for coordination detection
            self.coordination_detector.record(request).await;

            // Record for session analysis
            self.session_analyzer.record(request).await;
        }

        // Record for agent profiling (always — agent profiles are bounded separately)
        if let Some(agent_id) = agent_id {
            self.profiler.record(agent_id, request).await?;
        }

        // Record risk in memory (behavioral score as proxy)
        self.risk_memory.record(request.client_ip, 0.0, &request.path);

        Ok(())
    }

    /// Record risk score for an IP (called after analysis completes)
    pub fn record_risk(&self, ip: IpAddr, score: f64, path: &str) {
        self.risk_memory.record(ip, score, path);
    }

    /// Feature di timing per-IP (burst_score, inter_request_stddev_ms) per il threat_classifier.
    /// Esposte al decision-path → arricchiscono ml_features (2 feature che prima erano 0).
    pub fn timing_features(&self, ip: IpAddr) -> (f32, f32) {
        self.behavior_graph.timing_features(ip)
    }

    /// F4: Record the HTTP response status to feed Rule 1 (4xx burst detection).
    /// Returns a detection if the IP just crossed the 4xx-burst threshold.
    /// The detection (if any) is also appended to the event_log for JSONL emission.
    pub fn record_response(&self, ip: IpAddr, status: u16) -> Option<RuleDetection> {
        let detection = self.layer3.record_4xx(ip, status)?;
        self.event_log.insert(detection.event_id, detection.clone());
        Some(detection)
    }

    /// F4: Bridge a cross-IP signature detection into Layer 3 (Rule 5).
    /// Called by sentinel-server when cross_ip_correlator emits a botnet/coordinated pattern.
    pub fn record_cross_ip_signature(
        &self,
        ip: IpAddr,
        pattern_type: &str,
        evidence_count: usize,
    ) -> RuleDetection {
        let detection = self.layer3.record_cross_ip_signature(ip, pattern_type, evidence_count);
        self.event_log.insert(detection.event_id, detection.clone());
        detection
    }

    /// F4 accessor: Layer 3 rules engine (for stats/observability)
    pub fn layer3(&self) -> &Layer3Rules {
        &self.layer3
    }

    /// F6: Drain pending JSONL events for LoRA training pipeline.
    /// Returns a Vec of `RuleDetection` events newer than `since_event_id`.
    /// Caller (sentinel-server) is responsible for persisting them to disk.
    pub fn drain_events_since(&self, since_event_id: u64) -> Vec<RuleDetection> {
        let mut out: Vec<RuleDetection> = self
            .event_log
            .iter()
            .filter(|e| *e.key() > since_event_id)
            .map(|e| e.value().clone())
            .collect();
        out.sort_by_key(|e| e.event_id);
        out
    }

    /// Snapshot INCREMENTALE delle baseline anomaly modificate (per il flush periodico →
    /// Portal). Best-effort: il drain svuota il dirty-set e il chiamante invia
    /// fire-and-forget; se il POST fallisce quel batch è perso, ma lo stato è CUMULATIVO →
    /// la prossima `observe()` del tenant lo re-invia aggiornato (vedi BaselineStore::drain_dirty).
    pub fn drain_anomaly_baselines(&self) -> Vec<crate::anomaly_baseline::BaselineSnapshot> {
        self.anomaly_detector.baseline_snapshot_dirty()
    }

    /// Snapshot COMPLETO di TUTTE le baseline (non solo le dirty) — per il flush FINALE
    /// allo shutdown: cattura lo stato più aggiornato di ogni tenant così un SIGTERM non
    /// perde l'apprendimento dall'ultimo flush periodico. NON azzera il dirty-set.
    pub fn snapshot_anomaly_baselines(&self) -> Vec<crate::anomaly_baseline::BaselineSnapshot> {
        self.anomaly_detector.baseline_snapshot_all()
    }

    /// Restore delle baseline anomaly al boot (dai dati persistiti sul Portal) → il WAF non
    /// riparte cieco dopo un restart.
    pub fn restore_anomaly_baselines(&self, snaps: Vec<crate::anomaly_baseline::BaselineSnapshot>) {
        self.anomaly_detector.restore_baseline(snaps);
    }

    /// Get risk memory pre-scoring for an IP+path
    pub fn pre_score(&self, ip: IpAddr, path: &str) -> RiskMemoryResult {
        self.risk_memory.pre_score(ip, path)
    }

    /// Get path criticality
    pub fn path_criticality(&self, path: &str) -> PathCriticality {
        classify_path(path)
    }

    /// Get agent profile
    pub async fn get_profile(&self, agent_id: &AgentId) -> Option<AgentBehavior> {
        self.profiler.get_profile(agent_id).await
    }

    /// Get cross-IP correlator (for stats/observability)
    pub fn cross_ip_correlator(&self) -> &CrossIpCorrelator {
        &self.cross_ip_correlator
    }

    /// Get identity graph (for stats/observability)
    pub fn identity_graph(&self) -> &IdentityGraph {
        &self.identity_graph
    }

    /// Get intent detector (for stats/observability)
    pub fn intent_detector(&self) -> &IntentDetector {
        &self.intent_detector
    }

    /// Periodic cleanup of all behavioral data
    pub fn cleanup(&self) {
        self.behavior_graph.cleanup();
        self.risk_memory.cleanup();
        self.session_path_analyzer.cleanup();
        self.cross_ip_correlator.cleanup();
        self.identity_graph.cleanup();
        self.intent_detector.cleanup();
        self.layer3.cleanup();
        // F6: cap event_log to last 50k events (oldest evicted)
        if self.event_log.len() > 50_000 {
            let mut ids: Vec<u64> = self.event_log.iter().map(|e| *e.key()).collect();
            ids.sort_unstable();
            let to_drop = self.event_log.len() - 50_000;
            for id in ids.iter().take(to_drop) {
                self.event_log.remove(id);
            }
        }

        // A7: RECLAIM timing profiles — remove entries older than 30 min. Il cap
        // MAX_SESSIONS è ora strutturale in `ShardedLru` (evict LRU O(1) all'inserimento)
        // → niente più batch-evict O(n log n) (collect+sort) qui.
        self.timing_profiles.retain(|_, profile| {
            profile.last_request.elapsed().as_secs() < 1800
        });
    }

    /// Numero di timing-profile tracciati (per i test del bound SESSION1).
    #[cfg(test)]
    pub fn timing_profiles_len(&self) -> usize {
        self.timing_profiles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_behavioral_analysis_creation() {
        let config = BehaviorConfig::default();
        let analysis = BehavioralAnalysis::new(config);
        assert!(analysis.is_ok());
    }

    /// 🚨 SESSION1/OOM: la mappa timing_profiles (IP-keyed) è bounded realtime via
    /// ShardedLru (cap MAX_SESSIONS), non più via batch-evict O(n log n) periodico.
    /// Mutation-verify: revert a DashMap → timing_profiles_len() == 5200 invece di <= cap.
    #[tokio::test]
    async fn timing_profiles_bounded_realtime_under_ip_flood() {
        use std::net::{IpAddr, Ipv4Addr};
        let analysis = BehavioralAnalysis::new(BehaviorConfig::default()).unwrap();
        // > MAX_SESSIONS IP distinti → la mappa satura al cap (ogni analyze registra).
        for i in 0..5200u32 {
            let b = i.to_be_bytes();
            let req = Request {
                client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, b[2], b[3])),
                ..Default::default()
            };
            let _ = analysis.analyze(&req, None).await;
        }
        let n = analysis.timing_profiles_len();
        assert!(
            n <= MAX_SESSIONS && n > 4000,
            "timing_profiles non bounded realtime: {n} (atteso <= {MAX_SESSIONS})"
        );
    }

    #[test]
    fn test_timing_cv_too_regular() {
        let mut profile = TimingProfile::new();
        // Simulate very regular intervals (bot-like)
        for _ in 0..10 {
            profile.intervals.push_back(100.0); // Exactly 100ms each
            profile.request_count += 1;
        }

        let cv = profile.coefficient_of_variation().unwrap();
        assert!(cv < 0.1, "CV should be < 0.1 for perfectly regular intervals, got {}", cv);

        let (risk, _) = profile.analyze();
        assert!(risk > 0.0, "Should detect bot-like regularity");
        assert!(risk <= TIMING_MAX_CONTRIBUTION, "Risk should be capped at {}", TIMING_MAX_CONTRIBUTION);
    }

    #[test]
    fn test_timing_cv_human_like() {
        let mut profile = TimingProfile::new();
        // Simulate human-like variable intervals
        let intervals = [350.0, 1200.0, 450.0, 2000.0, 800.0, 150.0, 3500.0, 600.0];
        for &interval in &intervals {
            profile.intervals.push_back(interval);
            profile.request_count += 1;
        }

        let cv = profile.coefficient_of_variation().unwrap();
        assert!(cv > 0.5, "CV should be > 0.5 for human-like intervals, got {}", cv);

        let (risk, _) = profile.analyze();
        assert_eq!(risk, 0.0, "Should not flag human-like timing");
    }

    #[test]
    fn test_timing_superhuman_speed() {
        let mut profile = TimingProfile::new();
        // Simulate superhuman speed (< 200ms mean)
        for _ in 0..10 {
            profile.intervals.push_back(50.0 + (profile.intervals.len() as f64) * 5.0);
            profile.request_count += 1;
        }

        let mean = profile.mean_interval_ms().unwrap();
        assert!(mean < 200.0, "Mean should be < 200ms for superhuman speed");

        let (risk, _) = profile.analyze();
        assert!(risk > 0.0, "Should detect superhuman speed");
        assert!(risk <= TIMING_MAX_CONTRIBUTION, "Risk should be capped");
    }

    #[test]
    fn test_timing_insufficient_data() {
        let mut profile = TimingProfile::new();
        profile.intervals.push_back(100.0);
        profile.request_count = 2;

        let cv = profile.coefficient_of_variation();
        assert!(cv.is_none(), "Should not compute CV with < 3 requests");

        let (risk, _) = profile.analyze();
        assert_eq!(risk, 0.0, "Should return 0 risk with insufficient data");
    }

    // ── F4 (2026-06-02): Layer 3 wiring verification (record_response,
    //     drain_events_since, record_cross_ip_signature accessors) ────

    use std::net::Ipv4Addr;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> std::net::IpAddr {
        std::net::IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[tokio::test]
    async fn record_response_4xx_burst_triggers_detection_and_logs_event() {
        let config = BehaviorConfig::default();
        let ba = BehavioralAnalysis::new(config).unwrap();
        let ip = ipv4(203, 0, 113, 50);

        // Sotto-soglia: 19 hit 4xx → niente detection
        for _ in 0..19 {
            assert!(ba.record_response(ip, 404).is_none(), "below threshold");
        }
        // 20esimo hit → soglia → detection deve scattare
        let detection = ba.record_response(ip, 403);
        let d = detection.expect("20esimo 4xx deve triggerare rule 1");
        assert_eq!(d.rule_id, "behavioral.4xx_burst");
        assert!(d.severity_score >= 0.85);
        assert_eq!(d.decision_label, "ban_immediate");
        assert!(d.event_id > 0);

        // Drain: l'evento è in event_log
        let events = ba.drain_events_since(0);
        assert!(!events.is_empty(), "drain deve restituire l'evento");
        assert!(events.iter().any(|e| e.rule_id == "behavioral.4xx_burst"));
    }

    #[tokio::test]
    async fn record_response_ignores_2xx_3xx_5xx_status() {
        let ba = BehavioralAnalysis::new(BehaviorConfig::default()).unwrap();
        let ip = ipv4(203, 0, 113, 51);
        for _ in 0..30 {
            assert!(ba.record_response(ip, 200).is_none(), "2xx must not count");
            assert!(ba.record_response(ip, 301).is_none(), "3xx must not count");
            assert!(ba.record_response(ip, 500).is_none(), "5xx must not count");
        }
        // Nessun event_id consumato per status non-4xx
        let events = ba.drain_events_since(0);
        assert!(events.is_empty(), "non-4xx status must NEVER trigger rule 1");
    }

    #[tokio::test]
    async fn record_cross_ip_signature_creates_event_with_high_severity() {
        let ba = BehavioralAnalysis::new(BehaviorConfig::default()).unwrap();
        let ip = ipv4(203, 0, 113, 60);

        let d = ba.record_cross_ip_signature(ip, "botnet", 25);
        assert_eq!(d.rule_id, "behavioral.slow_distributed");
        assert!(d.severity_score >= 0.85, "cross-ip pattern = high severity");
        assert_eq!(d.evidence_count, 25);

        let events = ba.drain_events_since(0);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id, "behavioral.slow_distributed");
    }

    #[tokio::test]
    async fn drain_events_since_respects_cursor_and_returns_sorted() {
        let ba = BehavioralAnalysis::new(BehaviorConfig::default()).unwrap();
        let ip = ipv4(203, 0, 113, 70);

        // Genera 3 detection in sequenza
        for _ in 0..20 { ba.record_response(ip, 404); }
        let e1 = ba.drain_events_since(0);
        let last_id_1 = e1.iter().map(|e| e.event_id).max().unwrap();

        let _ = ba.record_cross_ip_signature(ip, "coordinated_attack", 10);
        let e2 = ba.drain_events_since(last_id_1);
        assert!(e2.iter().all(|e| e.event_id > last_id_1),
                "drain_events_since deve filtrare per cursore");
        assert_eq!(e2.len(), 1, "solo l'evento nuovo");

        // Ordinamento: ascending by event_id
        let _ = ba.record_cross_ip_signature(ip, "slow_distributed_low_rate", 30);
        let _ = ba.record_cross_ip_signature(ip, "botnet", 40);
        let all = ba.drain_events_since(0);
        let ids: Vec<u64> = all.iter().map(|e| e.event_id).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort();
        assert_eq!(ids, sorted_ids, "drain_events_since deve essere sorted ascending");
    }

    #[tokio::test]
    async fn event_log_capped_at_50k_via_cleanup() {
        let ba = BehavioralAnalysis::new(BehaviorConfig::default()).unwrap();
        // Pre-popola event_log con 50_010 entry sintetiche
        for i in 1..=50_010_u64 {
            ba.event_log.insert(i, RuleDetection {
                event_id: i,
                detected_at_epoch_secs: 0,
                rule_id: "synthetic",
                severity_score: 0.5,
                ip: "1.2.3.4".to_string(),
                evidence_count: 1,
                time_window_sec: 60,
                human_description: format!("synth-{i}"),
                decision_label: "monitor_increment_score",
            });
        }
        assert_eq!(ba.event_log.len(), 50_010);
        ba.cleanup();
        assert!(ba.event_log.len() <= 50_000, "cleanup deve evict oltre 50k");
    }
}
