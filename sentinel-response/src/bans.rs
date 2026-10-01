//! Ban Management
//!
//! Manages IP and agent bans with automatic expiration. Persistenza al
//! Portal API tramite fire-and-forget `PortalClient` (vedi crate
//! sentinel-persistence). Senza persistence client, il manager funziona
//! come prima (log-only in-memory).

use sentinel_core::{AgentId, ResponseConfig, SentinelError};
use dashmap::DashMap;
use sentinel_persistence::{BanPayload, BumpPayload, PortalClient, ThreatPayload, ThreatSeverity};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// IP infrastruttura/owner fidati, da `SENTINEL_TRUSTED_IPS` (CSV). Mai bannati.
/// Letti una sola volta (lazy). Esempio:
///   SENTINEL_TRUSTED_IPS="2001:db8::2,203.0.113.10"
fn trusted_ips() -> &'static Vec<IpAddr> {
    static TRUSTED: OnceLock<Vec<IpAddr>> = OnceLock::new();
    TRUSTED.get_or_init(|| {
        std::env::var("SENTINEL_TRUSTED_IPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect()
    })
}

/// True se l'IP NON deve MAI essere bannato né considerato bannato:
///  - unspecified (`0.0.0.0`, `::`) → IP placeholder: il gateway LLM lo usa per
///    le richieste server-to-server senza client reale; bannarlo significherebbe
///    bloccare TUTTI i tenant (incident 2026-06-06);
///  - loopback (`127.0.0.1`, `::1`) → traffico interno;
///  - IP in `SENTINEL_TRUSTED_IPS` → owner/infrastruttura.
pub fn is_unbannable(ip: &IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || trusted_ips().contains(ip)
}

/// Reason for ban
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// Critical risk score
    CriticalRisk,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Failed too many challenges
    ChallengeFailed,
    /// Manual ban by admin
    Manual,
    /// Coordinated attack detected
    CoordinatedAttack,
    /// Prompt injection attempt
    PromptInjection,
    /// Honeypot endpoint triggered (repeated scanner probing)
    HoneypotTriggered,
    /// G21.1: behavioral 4xx burst (Layer 3 Rule 1, severity >= 0.85).
    /// Heuristico su pattern di risposta — possibile falso positivo su
    /// utenti reali, quindi a BASSA confidenza per lo spike-breaker.
    Behavioral4xxBurst,
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanReason::CriticalRisk => write!(f, "Critical security risk"),
            BanReason::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            BanReason::ChallengeFailed => write!(f, "Failed security challenge"),
            BanReason::Manual => write!(f, "Manual ban"),
            BanReason::CoordinatedAttack => write!(f, "Coordinated attack detected"),
            BanReason::PromptInjection => write!(f, "Prompt injection attempt"),
            BanReason::HoneypotTriggered => write!(f, "Honeypot endpoint triggered"),
            BanReason::Behavioral4xxBurst => write!(f, "Behavioral 4xx burst detected"),
        }
    }
}

/// Ban entry
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// Reason for ban
    pub reason: BanReason,
    /// When banned
    pub banned_at: Instant,
    /// When ban expires
    pub expires_at: Instant,
    /// Number of times banned
    pub ban_count: u32,
}

/// Mappa BanReason → source field di security_bans (allineato a
/// `apps/portal/src/services/sentinel/record-ban.ts`).
fn ban_source(reason: BanReason) -> &'static str {
    match reason {
        BanReason::HoneypotTriggered => "sentinel_honeypot",
        BanReason::PromptInjection => "sentinel_neural",
        BanReason::CoordinatedAttack => "sentinel_behavior",
        BanReason::CriticalRisk => "sentinel_escalation",
        BanReason::RateLimitExceeded => "sentinel_edge",
        BanReason::ChallengeFailed => "sentinel_response",
        BanReason::Manual => "manual",
        BanReason::Behavioral4xxBurst => "sentinel_behavior",
    }
}

/// Mappa BanReason → trigger field (causal breve per il DB).
fn ban_trigger(reason: BanReason) -> &'static str {
    match reason {
        BanReason::HoneypotTriggered => "honeypot_3_hits",
        BanReason::PromptInjection => "prompt_injection_detected",
        BanReason::CoordinatedAttack => "coordinated_attack_detected",
        BanReason::CriticalRisk => "critical_risk_score",
        BanReason::RateLimitExceeded => "rate_limit_exceeded",
        BanReason::ChallengeFailed => "challenge_failed",
        BanReason::Manual => "manual_admin_ban",
        BanReason::Behavioral4xxBurst => "behavioral_4xx_burst",
    }
}

/// Risk score iniziale (0..100) per ogni reason.
fn ban_risk_score(reason: BanReason) -> i32 {
    match reason {
        BanReason::CriticalRisk => 100,
        BanReason::CoordinatedAttack => 95,
        BanReason::PromptInjection => 90,
        BanReason::HoneypotTriggered => 85,
        BanReason::ChallengeFailed => 70,
        BanReason::RateLimitExceeded => 60,
        BanReason::Manual => 100,
        BanReason::Behavioral4xxBurst => 85,
    }
}

/// Confidence (0..1) di ogni reason.
fn ban_confidence(reason: BanReason) -> f64 {
    match reason {
        BanReason::HoneypotTriggered => 0.99, // honeypot path inequivocabile
        BanReason::Manual => 1.0,
        BanReason::CriticalRisk => 0.95,
        BanReason::PromptInjection => 0.92,
        BanReason::CoordinatedAttack => 0.90,
        BanReason::ChallengeFailed => 0.85,
        BanReason::RateLimitExceeded => 0.80,
        BanReason::Behavioral4xxBurst => 0.85, // heuristico: FP possibile su burst 4xx legittimi
    }
}

/// Mappa BanReason → tipo di minaccia (snake_case stabile per `security_threats`),
/// oppure `None` se il ban NON è una detection (es. `Manual` = azione admin, non
/// una minaccia rilevata → non va nel feed minacce).
fn ban_threat_type(reason: BanReason) -> Option<&'static str> {
    match reason {
        BanReason::Manual => None,
        BanReason::HoneypotTriggered => Some("honeypot_scan"),
        BanReason::PromptInjection => Some("prompt_injection"),
        BanReason::CoordinatedAttack => Some("coordinated_attack"),
        BanReason::CriticalRisk => Some("critical_risk"),
        BanReason::RateLimitExceeded => Some("rate_limit_abuse"),
        BanReason::ChallengeFailed => Some("challenge_failed"),
        BanReason::Behavioral4xxBurst => Some("behavioral_anomaly"),
    }
}

/// Severità della minaccia. Derivata dal risk_score per coerenza con la scala
/// di rischio del ban (≥90 critical, ≥75 high, ≥60 medium, else low).
fn ban_threat_severity(reason: BanReason) -> ThreatSeverity {
    match ban_risk_score(reason) {
        s if s >= 90 => ThreatSeverity::Critical,
        s if s >= 75 => ThreatSeverity::High,
        s if s >= 60 => ThreatSeverity::Medium,
        _ => ThreatSeverity::Low,
    }
}

impl BanEntry {
    fn new(reason: BanReason, duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            reason,
            banned_at: now,
            expires_at: now + duration,
            ban_count: 1,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Get time remaining until ban expires
    pub fn time_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    fn extend(&mut self, reason: BanReason, duration: Duration) {
        self.reason = reason;
        self.expires_at = Instant::now() + duration;
        self.ban_count += 1;
    }
}

/// G21.1: callback invocata a ogni ban IP EFFETTIVO (dopo il gate
/// `is_unbannable`). Riceve (ip, reason) e DEVE essere veloce e non-bloccante:
/// gira inline nell'hot path di `ban_ip`. Usata dal server per alimentare lo
/// spike-breaker con la confidenza del ban (vedi sentinel-server main.rs).
pub type BanNotifier = Box<dyn Fn(IpAddr, BanReason) + Send + Sync>;

/// Ban manager
pub struct BanManager {
    /// IP bans
    ip_bans: Arc<DashMap<IpAddr, BanEntry>>,
    /// Agent bans
    agent_bans: Arc<DashMap<AgentId, BanEntry>>,
    /// Configuration
    #[allow(dead_code)]
    config: ResponseConfig,
    /// Optional persistence client (fire-and-forget) → Portal API.
    /// `None` = log-only (legacy), `Some` = ban replicato in PostgreSQL
    /// via POST /api/v1/internal/sentinel/ban.
    persistence: Option<PortalClient>,
    /// G21.1: observer dei ban — punto di convergenza di TUTTI i path che
    /// bannano (honeypot handler, 4xx-burst, CriticalRisk dentro
    /// determine_action, manual API). Set-once al boot, no-op se assente.
    ban_notifier: OnceLock<BanNotifier>,
}

impl BanManager {
    /// Create new ban manager (NO persistence — legacy log-only path).
    pub fn new(config: &ResponseConfig) -> Result<Self, SentinelError> {
        Ok(Self {
            ip_bans: Arc::new(DashMap::new()),
            agent_bans: Arc::new(DashMap::new()),
            config: config.clone(),
            persistence: None,
            ban_notifier: OnceLock::new(),
        })
    }

    /// G21.1: registra l'observer dei ban. Set-once: una seconda chiamata è
    /// no-op (ritorna false) — il breaker va registrato UNA volta al boot.
    pub fn set_ban_notifier(&self, notifier: BanNotifier) -> bool {
        self.ban_notifier.set(notifier).is_ok()
    }

    /// Create new ban manager con persistenza al Portal API.
    /// Quando `persistence` è `Some`, ogni nuovo ban genera POST
    /// /api/v1/internal/sentinel/ban verso il Portal Hono (fire-and-forget).
    pub fn with_persistence(
        config: &ResponseConfig,
        persistence: PortalClient,
    ) -> Result<Self, SentinelError> {
        Ok(Self {
            ban_notifier: OnceLock::new(),
            ip_bans: Arc::new(DashMap::new()),
            agent_bans: Arc::new(DashMap::new()),
            config: config.clone(),
            persistence: Some(persistence),
        })
    }

    /// Check if IP is banned. Quando il ban è hit (true), notifica il
    /// Portal per bumpBanCounter (fire-and-forget, non blocca il path).
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        // IP placeholder/loopback/trusted non sono MAI bannati (vedi is_unbannable).
        if is_unbannable(ip) {
            return false;
        }
        if let Some(entry) = self.ip_bans.get(ip) {
            if entry.is_expired() {
                drop(entry);
                self.ip_bans.remove(ip);
                false
            } else {
                // Ban hit: bump counter su Portal (best-effort)
                if let Some(persistence) = &self.persistence {
                    persistence.send_bump(BumpPayload {
                        ip_address: ip.to_string(),
                    });
                }
                true
            }
        } else {
            false
        }
    }

    /// Check if agent is banned
    pub async fn is_agent_banned(&self, agent_id: &AgentId) -> bool {
        if let Some(entry) = self.agent_bans.get(agent_id) {
            if entry.is_expired() {
                drop(entry);
                self.agent_bans.remove(agent_id);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Ban an IP. Replica in PostgreSQL via Portal API se persistenza
    /// attiva (fire-and-forget, mai blocca il WAF hot path).
    /// Ban di un IP. Variante semplice senza feature ML (la maggior parte dei call-site:
    /// ban behavioral/manual/rate-limit che non hanno il contesto-richiesta).
    pub async fn ban_ip(&self, ip: IpAddr, reason: BanReason, duration: Duration) {
        self.ban_ip_with_features(ip, reason, duration, None).await;
    }

    /// Come `ban_ip`, ma allega il vettore RAW 18-feature alla riga `security_threats`
    /// (per il training del threat_classifier). Lo passa SOLO il decision-path che ha la
    /// Request completa (determine_action → process). `ml_features=None` ⇒ identico a `ban_ip`.
    pub async fn ban_ip_with_features(
        &self,
        ip: IpAddr,
        reason: BanReason,
        duration: Duration,
        ml_features: Option<serde_json::Value>,
    ) {
        // MAI bannare IP placeholder/loopback/trusted: '0.0.0.0' è l'IP usato dal
        // gateway LLM per le richieste server-to-server senza client reale —
        // bannarlo bloccava TUTTI i tenant (incident 2026-06-06).
        if is_unbannable(&ip) {
            tracing::debug!(ip = %ip, reason = %reason, "ban skipped — IP unbannable (placeholder/loopback/trusted)");
            return;
        }
        // È un ban NUOVO (prima detection di questo IP, o ri-armato dopo scadenza)?
        // Solo i nuovi generano una riga `security_threats`: gli extend sono lo
        // STESSO IP che continua → non vogliamo floodare il feed minacce.
        let is_new_ban = !self.ip_bans.contains_key(&ip);
        self.ip_bans
            .entry(ip)
            .and_modify(|e| e.extend(reason, duration))
            .or_insert_with(|| BanEntry::new(reason, duration));

        tracing::warn!(
            ip = %ip,
            reason = %reason,
            duration_secs = duration.as_secs(),
            "IP banned"
        );

        // G21.1: notifica lo spike-breaker. DOPO is_unbannable (un ban
        // skippato non è un ban) e per ogni evento ban, anche extend di un
        // IP già bannato (il rate di EVENTI è il segnale del cascade).
        if let Some(notify) = self.ban_notifier.get() {
            notify(ip, reason);
        }

        // Fire-and-forget persistence → Portal → public.security_bans
        // → sync-banned-ips.sh → /etc/nginx/banned-ips.conf radix tree (≤60s)
        if let Some(persistence) = &self.persistence {
            persistence.send_ban(BanPayload {
                ip_address: ip.to_string(),
                source: ban_source(reason).to_string(),
                trigger: ban_trigger(reason).to_string(),
                reason: format!("{}", reason),
                evidence: None,
                trigger_path: None,
                trigger_pattern: None,
                user_agent: None,
                request_method: None,
                risk_score: Some(ban_risk_score(reason)),
                confidence: Some(ban_confidence(reason)),
                duration_hours: (duration.as_secs() / 3600).max(1) as i32,
                is_permanent: Some(false),
                country_code: None,
                threat_id: None,
            });

            // Fire-and-forget threat → Portal → public.security_threats.
            // Solo detection (non Manual) e solo su ban NUOVO → alimenta la tab
            // Threats di admin, che era ferma perché send_threat non era mai cablato.
            if is_new_ban {
                if let Some(threat_type) = ban_threat_type(reason) {
                    persistence.send_threat(ThreatPayload {
                        r#type: threat_type.to_string(),
                        severity: ban_threat_severity(reason),
                        ip_address: Some(ip.to_string()),
                        request_id: None,
                        confidence: ban_confidence(reason),
                        risk_score: ban_risk_score(reason) as f64,
                        detection_source: ban_source(reason).to_string(),
                        description: format!("{}", reason),
                        evidence: None,
                        raw_request: None,
                        action_taken: Some("ip_banned".to_string()),
                        action_details: None,
                        ml_features,
                    });
                }
            }
        }
    }

    /// Registra un CAMPIONE BENIGNO (traffico pulito) come classe NEGATIVA per il training
    /// del threat_classifier. Senza negativi il dataset è mono-classe → modello non
    /// addestrabile. Fire-and-forget verso il portal (type "benign_sample" → human_label
    /// 'benign' auto, lato portal). No-op se la persistence non è configurata.
    pub fn record_benign_sample(&self, ml_features: serde_json::Value) {
        let Some(persistence) = &self.persistence else { return };
        persistence.send_threat(ThreatPayload {
            r#type: "benign_sample".to_string(),
            severity: ThreatSeverity::Low,
            ip_address: None,
            request_id: None,
            confidence: 1.0,
            risk_score: 0.0,
            detection_source: "sampler".to_string(),
            description: "Campione benigno (traffico pulito) per la classe negativa del training".to_string(),
            evidence: None,
            raw_request: None,
            action_taken: Some("sampled".to_string()),
            action_details: None,
            ml_features: Some(ml_features),
        });
    }

    /// Ban an agent
    pub async fn ban_agent(&self, agent_id: AgentId, reason: BanReason, duration: Duration) {
        self.agent_bans
            .entry(agent_id.clone())
            .and_modify(|e| e.extend(reason, duration))
            .or_insert_with(|| BanEntry::new(reason, duration));

        tracing::warn!(
            agent_id = %agent_id,
            reason = %reason,
            duration_secs = duration.as_secs(),
            "Agent banned"
        );
    }

    /// Unban an IP
    pub async fn unban_ip(&self, ip: &IpAddr) {
        self.ip_bans.remove(ip);
        tracing::info!(ip = %ip, "IP unbanned");
    }

    /// Unban an agent
    pub async fn unban_agent(&self, agent_id: &AgentId) {
        self.agent_bans.remove(agent_id);
        tracing::info!(agent_id = %agent_id, "Agent unbanned");
    }

    /// Get time until IP unban
    pub async fn time_until_unban(&self, ip: &IpAddr) -> Duration {
        self.ip_bans
            .get(ip)
            .map(|e| e.time_remaining())
            .unwrap_or(Duration::ZERO)
    }

    /// Get time until agent unban
    pub async fn time_until_agent_unban(&self, agent_id: &AgentId) -> Duration {
        self.agent_bans
            .get(agent_id)
            .map(|e| e.time_remaining())
            .unwrap_or(Duration::ZERO)
    }

    /// Get ban info for IP
    pub async fn get_ban_info(&self, ip: &IpAddr) -> Option<BanEntry> {
        self.ip_bans.get(ip).map(|e| e.clone())
    }

    /// Get ban info for agent
    pub async fn get_agent_ban_info(&self, agent_id: &AgentId) -> Option<BanEntry> {
        self.agent_bans.get(agent_id).map(|e| e.clone())
    }

    /// Get active ban count
    pub fn active_ban_count(&self) -> usize {
        self.ip_bans.len() + self.agent_bans.len()
    }

    /// Get all banned IPs
    pub fn get_banned_ips(&self) -> Vec<(IpAddr, BanEntry)> {
        self.ip_bans
            .iter()
            .filter(|e| !e.value().is_expired())
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }

    /// Drop expired bans, returning how many entries were removed.
    ///
    /// Sync, not async: the body is two `retain` calls with nothing to await, and
    /// the periodic maintenance that calls it (`Sentinel::periodic_maintenance`)
    /// is itself sync — as is the behavioural layer's own `cleanup`.
    pub fn cleanup(&self) -> usize {
        let before = self.ip_bans.len() + self.agent_bans.len();
        self.ip_bans.retain(|_, e| !e.is_expired());
        self.agent_bans.retain(|_, e| !e.is_expired());
        before - (self.ip_bans.len() + self.agent_bans.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ban_ip() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(!manager.is_banned(&ip).await);

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;

        assert!(manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_unbannable_ips_never_banned() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        // 0.0.0.0 = placeholder usato dal gateway LLM per le richieste senza
        // client reale. Bannarlo bloccava TUTTI i tenant (incident 2026-06-06).
        let zero = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        manager.ban_ip(zero, BanReason::CriticalRisk, Duration::from_secs(86_400)).await;
        assert!(!manager.is_banned(&zero).await, "0.0.0.0 non deve MAI risultare bannato");

        // loopback (traffico interno) idem
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        manager.ban_ip(lo, BanReason::CriticalRisk, Duration::from_secs(60)).await;
        assert!(!manager.is_banned(&lo).await);

        // un IP pubblico normale resta bannabile
        assert!(is_unbannable(&zero));
        assert!(is_unbannable(&lo));
        assert!(!is_unbannable(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[tokio::test]
    async fn test_unban_ip() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;
        assert!(manager.is_banned(&ip).await);

        manager.unban_ip(&ip).await;
        assert!(!manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_ban_expiration() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Ban for very short duration
        manager.ban_ip(ip, BanReason::Manual, Duration::from_millis(1)).await;

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should be unbanned now
        assert!(!manager.is_banned(&ip).await);
    }

    #[tokio::test]
    async fn test_ban_count() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        manager.ban_ip(ip, BanReason::Manual, Duration::from_secs(60)).await;
        manager.ban_ip(ip, BanReason::RateLimitExceeded, Duration::from_secs(60)).await;

        let info = manager.get_ban_info(&ip).await.unwrap();
        assert_eq!(info.ban_count, 2);
    }

    // ── Mapper tests (allineamento con Portal record-ban.ts) ─────────

    #[test]
    fn test_ban_source_mapping() {
        // Mapping deve allinearsi col tipo source nello schema TS.
        assert_eq!(ban_source(BanReason::HoneypotTriggered), "sentinel_honeypot");
        assert_eq!(ban_source(BanReason::PromptInjection), "sentinel_neural");
        assert_eq!(ban_source(BanReason::CoordinatedAttack), "sentinel_behavior");
        assert_eq!(ban_source(BanReason::CriticalRisk), "sentinel_escalation");
        assert_eq!(ban_source(BanReason::RateLimitExceeded), "sentinel_edge");
        assert_eq!(ban_source(BanReason::ChallengeFailed), "sentinel_response");
        assert_eq!(ban_source(BanReason::Manual), "manual");
    }

    #[test]
    fn test_ban_trigger_distinct() {
        // Ogni reason ha un trigger distinto (no collision).
        let reasons = [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Manual,
        ];
        let mut triggers: Vec<&str> = reasons.iter().map(|r| ban_trigger(*r)).collect();
        triggers.sort();
        triggers.dedup();
        assert_eq!(triggers.len(), 7, "ogni reason deve avere un trigger unico");
    }

    #[test]
    fn test_ban_risk_score_range() {
        // Tutti gli score in 0..=100
        for reason in [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Manual,
        ] {
            let s = ban_risk_score(reason);
            assert!((0..=100).contains(&s), "score {} fuori range per {:?}", s, reason);
        }
    }

    #[test]
    fn test_ban_risk_score_critical_highest() {
        // CriticalRisk + Manual = 100 (massima severità)
        assert_eq!(ban_risk_score(BanReason::CriticalRisk), 100);
        assert_eq!(ban_risk_score(BanReason::Manual), 100);
        // RateLimit = bassa severità
        assert!(ban_risk_score(BanReason::RateLimitExceeded) < ban_risk_score(BanReason::CriticalRisk));
    }

    #[test]
    fn test_ban_confidence_range() {
        // Tutte le confidence in 0.0..=1.0
        for reason in [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Manual,
        ] {
            let c = ban_confidence(reason);
            assert!((0.0..=1.0).contains(&c), "confidence {} fuori range per {:?}", c, reason);
        }
    }

    #[test]
    fn test_ban_confidence_honeypot_highest_auto() {
        // Honeypot deve avere confidence quasi 1.0 (path inequivocabile)
        assert!(ban_confidence(BanReason::HoneypotTriggered) >= 0.99);
        // Manual è 1.0 esatto (admin sa quello che fa)
        assert_eq!(ban_confidence(BanReason::Manual), 1.0);
    }

    #[test]
    fn test_ban_reason_display() {
        // Display non vuoto per tutti
        for reason in [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Manual,
            BanReason::Behavioral4xxBurst,
        ] {
            assert!(!format!("{}", reason).is_empty());
        }
    }

    // ── G21.1: ban notifier (observer per lo spike-breaker) ──────────

    #[tokio::test]
    async fn notifier_fires_on_every_effective_ban_with_correct_reason() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let last_reason = Arc::new(parking_lot::Mutex::new(None::<BanReason>));
        let (c, r) = (calls.clone(), last_reason.clone());
        assert!(manager.set_ban_notifier(Box::new(move |_ip, reason| {
            c.fetch_add(1, Ordering::SeqCst);
            *r.lock() = Some(reason);
        })), "primo set deve riuscire");

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        manager.ban_ip(ip, BanReason::Behavioral4xxBurst, Duration::from_secs(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "notifier deve scattare al primo ban");
        assert_eq!(*last_reason.lock(), Some(BanReason::Behavioral4xxBurst));

        // Extend (stesso IP ri-bannato) = nuovo EVENTO ban → notifica di
        // nuovo: il rate di eventi è il segnale del cascade.
        manager.ban_ip(ip, BanReason::CriticalRisk, Duration::from_secs(120)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "notifier deve scattare anche su extend");
        assert_eq!(*last_reason.lock(), Some(BanReason::CriticalRisk));
    }

    #[tokio::test]
    async fn notifier_does_not_fire_for_unbannable_ips() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        manager.set_ban_notifier(Box::new(move |_ip, _reason| {
            c.fetch_add(1, Ordering::SeqCst);
        }));

        // Un ban skippato (0.0.0.0/loopback) NON è un ban: se contasse,
        // il gateway LLM (che usa 0.0.0.0) potrebbe alimentare il breaker.
        manager.ban_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), BanReason::CriticalRisk, Duration::from_secs(60)).await;
        manager.ban_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), BanReason::CriticalRisk, Duration::from_secs(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "IP unbannable non deve notificare");
    }

    #[tokio::test]
    async fn notifier_is_set_once() {
        let config = ResponseConfig::default();
        let manager = BanManager::new(&config).unwrap();
        assert!(manager.set_ban_notifier(Box::new(|_, _| {})));
        assert!(!manager.set_ban_notifier(Box::new(|_, _| {})), "secondo set deve essere rifiutato");
    }

    #[tokio::test]
    async fn test_with_persistence_disabled_secret() {
        // Persistence client senza secret (env empty) = NO-OP, ma il
        // BanManager deve comunque funzionare in-memory.
        std::env::remove_var("SENTINEL_INTERNAL_SECRET");
        let config = ResponseConfig::default();
        let client = sentinel_persistence::PortalClient::spawn(
            sentinel_persistence::PortalClientConfig::from_env(),
        );
        let manager = BanManager::with_persistence(&config, client).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        manager.ban_ip(ip, BanReason::HoneypotTriggered, Duration::from_secs(60)).await;
        assert!(manager.is_banned(&ip).await);
    }

    // ── Threat emission: BanReason → security_threats (mapper PURO) ───
    // Anti-regressione del bug "send_threat mai cablato": la tab Threats di
    // admin era ferma dal 26 maggio perché nessuna detection persisteva.

    #[test]
    fn test_ban_threat_type_manual_is_not_a_threat() {
        // Manual = azione admin, NON una detection → niente riga threats.
        assert_eq!(ban_threat_type(BanReason::Manual), None);
    }

    #[test]
    fn test_ban_threat_type_every_detection_maps() {
        // Ogni detection (≠ Manual) DEVE produrre un tipo threat (mai None).
        for reason in [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Behavioral4xxBurst,
        ] {
            assert!(ban_threat_type(reason).is_some(), "detection {:?} senza threat type", reason);
        }
        assert_eq!(ban_threat_type(BanReason::HoneypotTriggered), Some("honeypot_scan"));
        assert_eq!(ban_threat_type(BanReason::PromptInjection), Some("prompt_injection"));
    }

    #[test]
    fn test_ban_threat_type_distinct() {
        // Nessuna collisione tra i tipi delle detection.
        let mut types: Vec<&str> = [
            BanReason::HoneypotTriggered,
            BanReason::PromptInjection,
            BanReason::CoordinatedAttack,
            BanReason::CriticalRisk,
            BanReason::RateLimitExceeded,
            BanReason::ChallengeFailed,
            BanReason::Behavioral4xxBurst,
        ]
        .iter()
        .filter_map(|r| ban_threat_type(*r))
        .collect();
        let n = types.len();
        types.sort();
        types.dedup();
        assert_eq!(types.len(), n, "tipi threat devono essere unici");
        assert_eq!(n, 7);
    }

    #[test]
    fn test_ban_threat_severity_follows_risk_score() {
        // Severità coerente con la scala risk (≥90 crit, ≥75 high, ≥60 med).
        assert!(matches!(ban_threat_severity(BanReason::CriticalRisk), ThreatSeverity::Critical)); // 100
        assert!(matches!(ban_threat_severity(BanReason::CoordinatedAttack), ThreatSeverity::Critical)); // 95
        assert!(matches!(ban_threat_severity(BanReason::PromptInjection), ThreatSeverity::Critical)); // 90
        assert!(matches!(ban_threat_severity(BanReason::HoneypotTriggered), ThreatSeverity::High)); // 85
        assert!(matches!(ban_threat_severity(BanReason::Behavioral4xxBurst), ThreatSeverity::High)); // 85
        assert!(matches!(ban_threat_severity(BanReason::ChallengeFailed), ThreatSeverity::Medium)); // 70 → ≥60
        assert!(matches!(ban_threat_severity(BanReason::RateLimitExceeded), ThreatSeverity::Medium)); // 60
    }

    // ── Wiring E2E (wiremock): ban_ip DEVE chiamare send_threat ──────

    fn persistence_to(server_uri: String) -> sentinel_persistence::PortalClient {
        sentinel_persistence::PortalClient::spawn(sentinel_persistence::PortalClientConfig {
            base_url: server_uri,
            secret: "test-secret".to_string(),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn ban_ip_detection_persists_threat() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/threat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "ok": true, "threatId": "t-1" }),
            ))
            .expect(1) // ESATTAMENTE una threat per la detection
            .mount(&server)
            .await;
        // assorbe anche il /ban (non lo contiamo qui)
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/ban"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let config = ResponseConfig::default();
        let manager = BanManager::with_persistence(&config, persistence_to(server.uri())).unwrap();
        manager
            .ban_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), BanReason::HoneypotTriggered, Duration::from_secs(60))
            .await;

        tokio::time::sleep(Duration::from_millis(250)).await;
        // drop(server) verifica .expect(1) → fallisce se send_threat non è cablato.
    }

    #[tokio::test]
    async fn ban_ip_with_features_attaches_ml_features_to_threat() {
        // ANTI-ASPIRAZIONALE (5b): se le feature passate NON arrivano nel POST come
        // `mlFeatures`, il dataset di training resta vuoto → questo test diventa rosso.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/threat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "threatId": "t-2" })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/ban"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let config = ResponseConfig::default();
        let manager = BanManager::with_persistence(&config, persistence_to(server.uri())).unwrap();
        let features = serde_json::json!({ "risk_score": 0.9, "threat_type": "sqli" });
        manager
            .ban_ip_with_features(
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                BanReason::HoneypotTriggered,
                Duration::from_secs(60),
                Some(features),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(250)).await;

        let reqs = server.received_requests().await.unwrap();
        let threat = reqs
            .iter()
            .find(|r| r.url.path() == "/api/v1/internal/sentinel/threat")
            .expect("nessun POST threat ricevuto");
        let body: serde_json::Value = serde_json::from_slice(&threat.body).unwrap();
        assert!(body.get("mlFeatures").is_some(), "il threat DEVE portare mlFeatures (camelCase)");
        assert_eq!(body["mlFeatures"]["risk_score"], 0.9, "le feature passate devono arrivare intatte");
    }

    #[tokio::test]
    async fn record_benign_sample_posts_negative_class() {
        // #4 classe NEGATIVA: il campione benigno DEVE arrivare al portal come type
        // "benign_sample" con mlFeatures → senza, il dataset è mono-classe (non addestrabile).
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/threat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "threatId": "b-1" })))
            .mount(&server)
            .await;

        let config = ResponseConfig::default();
        let manager = BanManager::with_persistence(&config, persistence_to(server.uri())).unwrap();
        manager.record_benign_sample(serde_json::json!({ "risk_score": 0.0, "threat_type": "none" }));

        tokio::time::sleep(Duration::from_millis(250)).await;
        let reqs = server.received_requests().await.unwrap();
        let threat = reqs.iter().find(|r| r.url.path() == "/api/v1/internal/sentinel/threat").expect("nessun POST benign");
        let body: serde_json::Value = serde_json::from_slice(&threat.body).unwrap();
        assert_eq!(body["type"], "benign_sample");
        assert!(body.get("mlFeatures").is_some(), "il campione benigno deve portare le feature");
    }

    #[tokio::test]
    async fn ban_ip_manual_does_not_persist_threat() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/threat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .expect(0) // Manual NON è una detection → zero threat
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/ban"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let config = ResponseConfig::default();
        let manager = BanManager::with_persistence(&config, persistence_to(server.uri())).unwrap();
        manager
            .ban_ip(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), BanReason::Manual, Duration::from_secs(60))
            .await;

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    #[tokio::test]
    async fn ban_ip_extend_does_not_reflood_threats() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/threat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .expect(1) // 3 eventi sullo STESSO IP → 1 sola threat (solo il nuovo)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/sentinel/ban"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
            .mount(&server)
            .await;

        let config = ResponseConfig::default();
        let manager = BanManager::with_persistence(&config, persistence_to(server.uri())).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7));
        manager.ban_ip(ip, BanReason::HoneypotTriggered, Duration::from_secs(60)).await;
        manager.ban_ip(ip, BanReason::HoneypotTriggered, Duration::from_secs(60)).await;
        manager.ban_ip(ip, BanReason::RateLimitExceeded, Duration::from_secs(60)).await;

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
