//! IP Intelligence Module
//!
//! Provides IP reputation scoring and threat detection:
//! - Known attacker detection
//! - Tor exit node detection
//! - Proxy/VPN detection
//! - Botnet detection
//! - Geographic lookup (MaxMind GeoLite2-Country)
//! - ASN lookup (MaxMind GeoLite2-ASN) with hosting/datacenter classification

use sentinel_core::sharded_lru::ShardedLru;
use once_cell::sync::OnceCell;
use std::collections::HashSet;
use std::net::IpAddr;
use parking_lot::RwLock;
use std::time::{Duration, Instant};

/// Types of threats associated with an IP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatType {
    /// Known attacker from threat feeds
    KnownAttacker,
    /// Tor exit node
    TorExitNode,
    /// Proxy or VPN
    Proxy,
    /// Known scanner
    Scanner,
    /// Part of botnet
    Botnet,
}

/// IP reputation information
#[derive(Debug, Clone)]
pub struct IpReputation {
    /// Reputation score (0.0 = bad, 1.0 = good)
    pub score: f64,
    /// Detected threat type if any
    pub threat_type: Option<ThreatType>,
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// ASN number
    pub asn: Option<u32>,
    /// ASN organization name
    pub asn_org: Option<String>,
    /// Whether IP is from a hosting/datacenter provider
    pub is_hosting: bool,
    /// Whether IP is in blocklist
    pub is_blocked: bool,
    /// Block reason if blocked
    pub block_reason: Option<String>,
    /// When the block expires
    pub block_expires: Option<Instant>,
}

impl Default for IpReputation {
    fn default() -> Self {
        Self {
            score: 1.0,
            threat_type: None,
            country: None,
            asn: None,
            asn_org: None,
            is_hosting: false,
            is_blocked: false,
            block_reason: None,
            block_expires: None,
        }
    }
}

/// GeoIP country lookup result
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    /// ISO 3166-1 alpha-2 country code
    pub country_code: String,
    /// Risk contribution from country (0-20)
    pub risk_contribution: i32,
}

/// ASN lookup result
#[derive(Debug, Clone)]
pub struct AsnResult {
    /// Autonomous System Number
    pub asn: u32,
    /// Organization name
    pub org: String,
    /// Whether this is a hosting/cloud/VPS provider
    pub is_hosting: bool,
    /// Whether this is a residential ISP
    pub is_residential: bool,
    /// Risk contribution (0-20)
    pub risk_contribution: i32,
}

/// Block entry for an IP
struct BlockEntry {
    reason: String,
    expires: Option<Instant>,
    _created: Instant,
}

// ─── MaxMind GeoIP2 Readers (OnceCell — loaded once, zero I/O per-request) ──

/// Static GeoLite2-Country reader
static GEOIP_COUNTRY_READER: OnceCell<Option<maxminddb::Reader<Vec<u8>>>> = OnceCell::new();

/// Static GeoLite2-ASN reader
static GEOIP_ASN_READER: OnceCell<Option<maxminddb::Reader<Vec<u8>>>> = OnceCell::new();

fn get_country_reader() -> Option<&'static maxminddb::Reader<Vec<u8>>> {
    GEOIP_COUNTRY_READER
        .get_or_init(|| {
            let path = std::env::var("GEOIP_DB_PATH").ok()?;
            match maxminddb::Reader::open_readfile(&path) {
                Ok(reader) => {
                    tracing::info!(path = %path, "GeoLite2-Country database loaded");
                    Some(reader)
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "Failed to load GeoLite2-Country database");
                    None
                }
            }
        })
        .as_ref()
}

fn get_asn_reader() -> Option<&'static maxminddb::Reader<Vec<u8>>> {
    GEOIP_ASN_READER
        .get_or_init(|| {
            let path = std::env::var("GEOIP_ASN_PATH").ok()?;
            match maxminddb::Reader::open_readfile(&path) {
                Ok(reader) => {
                    tracing::info!(path = %path, "GeoLite2-ASN database loaded");
                    Some(reader)
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "Failed to load GeoLite2-ASN database");
                    None
                }
            }
        })
        .as_ref()
}

// ─── Country Risk Map ──────────────────────────────────────────────────────

/// Country risk classification
fn country_risk(code: &str) -> i32 {
    match code {
        // High risk — no commercial relationship, frequent attack source
        "RU" | "CN" | "KP" | "IR" => 15,
        // Elevated risk — occasional attack source
        "VN" | "IN" | "BR" | "ID" | "PK" | "BD" | "NG" | "UA" | "TH" | "PH" => 5,
        // Low risk — EU/EFTA + major commercial partners
        "IT" | "DE" | "FR" | "ES" | "NL" | "BE" | "AT" | "CH" | "GB" | "US" | "CA" | "JP"
        | "AU" | "SE" | "NO" | "DK" | "FI" | "IE" | "PT" | "PL" | "CZ" | "GR" | "HU"
        | "RO" | "BG" | "HR" | "SK" | "SI" | "LT" | "LV" | "EE" | "LU" | "MT" | "CY" => 0,
        // Unknown / other countries — slight caution
        _ => 3,
    }
}

// ─── ASN Hosting Provider Classification ───────────────────────────────────

/// Known hosting/cloud provider ASNs
const HOSTING_ASNS: &[u32] = &[
    // Major cloud providers
    16509, // Amazon AWS
    14618, // Amazon AWS (alternate)
    15169, // Google Cloud
    396982, // Google Cloud (alternate)
    8075,  // Microsoft Azure
    13335, // Cloudflare
    14061, // DigitalOcean
    20473, // Vultr / The Constant Company
    63949, // Linode / Akamai
    // European hosting
    24940, // Hetzner
    16276, // OVH
    51167, // Contabo
    197540, // Netcup
    47583, // Hostinger
    60781, // LeaseWeb
    // VPN/proxy heavy
    9009,  // M247 (common VPN/proxy)
    60068, // CDN77
    206264, // Amarutu Technology (common proxy)
    // Chinese cloud
    37963, // Alibaba Cloud
    45090, // Tencent Cloud
];

/// Known bulletproof hosting ASNs (high risk)
const BULLETPROOF_ASNS: &[u32] = &[
    49981,  // WorldStream
    209605, // UAB Host Baltic
    44477,  // Stark Industries Solutions
    60117,  // Host Sailor
    213371, // Squitter
];

fn classify_asn(asn: u32) -> (bool, bool, i32) {
    // Returns: (is_hosting, is_residential, risk_contribution)
    if BULLETPROOF_ASNS.contains(&asn) {
        (true, false, 20)
    } else if HOSTING_ASNS.contains(&asn) {
        (true, false, 10)
    } else {
        // Unknown ASN — assume residential
        (false, true, 0)
    }
}

// ─── MaxMind Deserialization Structs ────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct GeoCountryRecord {
    country: Option<GeoCountry>,
}

#[derive(Debug, serde::Deserialize)]
struct GeoCountry {
    iso_code: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GeoAsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

/// Cap HARD della blocklist (anti-OOM/SESSION1): IP-keyed, bound realtime via ShardedLru
/// (evict LRU O(1)). Pre-fix: DashMap senza cap di size (solo remove su unblock/expire).
const MAX_BLOCKLIST_ENTRIES: usize = 200_000;
/// Cap HARD della reputation-cache (anti-OOM/SESSION1): IP-keyed. Pre-fix: DashMap senza
/// cap (solo TTL su accesso) → un flood di IP distinti gonfiava la cache all'infinito.
const MAX_CACHE_ENTRIES: usize = 100_000;

/// IP Intelligence service
pub struct IpIntelligence {
    /// Manual blocklist. `ShardedLru` → bound HARD realtime (era DashMap senza cap size).
    blocklist: ShardedLru<IpAddr, BlockEntry>,
    /// Known Tor exit nodes
    tor_exits: RwLock<HashSet<IpAddr>>,
    /// Known proxy/VPN IPs
    proxies: RwLock<HashSet<IpAddr>>,
    /// Known scanner IPs
    scanners: RwLock<HashSet<IpAddr>>,
    /// Reputation cache. `ShardedLru` → bound HARD realtime (era DashMap, solo TTL).
    cache: ShardedLru<IpAddr, (IpReputation, Instant)>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl IpIntelligence {
    /// Create a new IP Intelligence service
    pub fn new() -> Self {
        Self {
            blocklist: ShardedLru::new(MAX_BLOCKLIST_ENTRIES),
            tor_exits: RwLock::new(HashSet::new()),
            proxies: RwLock::new(HashSet::new()),
            scanners: RwLock::new(HashSet::new()),
            cache: ShardedLru::new(MAX_CACHE_ENTRIES),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Check IP reputation (includes GeoIP + ASN)
    pub async fn check(&self, ip: IpAddr) -> IpReputation {
        // Check cache first (peek: non promuove inutilmente la recency su un hit scaduto).
        if let Some(rep) = self.cache.with_peek(&ip, |o| {
            o.filter(|e| e.1.elapsed() < self.cache_ttl).map(|e| e.0.clone())
        }) {
            return rep;
        }

        let mut reputation = IpReputation::default();

        // Check blocklist (Race #9 fix DD audit 2026-06-01).
        //
        // Pre-fix: `get(&ip)` ottiene una read ref, poi `drop(block)` +
        // `remove(&ip)` separati. Una thread tra drop e remove poteva fare
        // get → vedere entry ESPIRATA → settare reputation.is_blocked=true
        // mentre era logically expired. Inoltre double-remove possibile.
        //
        // Post-fix: `remove_if` atomico = single DashMap op che valuta predicato
        // e rimuove SOLO se predicate true. Ritorna Some(prev) solo se rimossa.
        // Successivo `get(&ip)` legge stato post-rimozione coerente.
        self.blocklist.remove_if(&ip, |block| {
            block.expires.is_some_and(|expires| Instant::now() >= expires)
        });
        if let Some((reason, expires)) =
            self.blocklist.with_peek(&ip, |o| o.map(|b| (b.reason.clone(), b.expires)))
        {
            // Qui sopravvivono SOLO entry valide (permanent OR not-yet-expired).
            reputation.is_blocked = true;
            reputation.block_reason = Some(reason);
            reputation.block_expires = expires;
            reputation.score = 0.0;
            reputation.threat_type = Some(ThreatType::KnownAttacker);
        }

        // Check Tor exits
        if !reputation.is_blocked {
            let tor_exits = self.tor_exits.read();
            if tor_exits.contains(&ip) {
                reputation.threat_type = Some(ThreatType::TorExitNode);
                reputation.score = 0.3;
            }
        }

        // Check proxies
        if !reputation.is_blocked && reputation.threat_type.is_none() {
            let proxies = self.proxies.read();
            if proxies.contains(&ip) {
                reputation.threat_type = Some(ThreatType::Proxy);
                reputation.score = 0.5;
            }
        }

        // Check scanners
        if !reputation.is_blocked && reputation.threat_type.is_none() {
            let scanners = self.scanners.read();
            if scanners.contains(&ip) {
                reputation.threat_type = Some(ThreatType::Scanner);
                reputation.score = 0.2;
            }
        }

        // GeoIP country lookup
        reputation.country = self.lookup_country(ip);

        // ASN lookup + hosting classification
        if let Some(asn_result) = self.lookup_asn(ip) {
            reputation.asn = Some(asn_result.asn);
            reputation.asn_org = Some(asn_result.org);
            reputation.is_hosting = asn_result.is_hosting;

            // Hosting providers reduce reputation score
            if asn_result.is_hosting && reputation.threat_type.is_none() {
                let penalty = asn_result.risk_contribution as f64 / 100.0;
                reputation.score = (reputation.score - penalty).max(0.3);
            }
        }

        // Cache the result
        self.cache.put(ip, (reputation.clone(), Instant::now()));

        reputation
    }

    /// Lookup country code for an IP using MaxMind GeoLite2-Country
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = get_country_reader()?;
        let lookup = reader.lookup(ip).ok()?;
        let record: GeoCountryRecord = lookup.decode().ok().flatten()?;
        record.country?.iso_code
    }

    /// Lookup ASN for an IP using MaxMind GeoLite2-ASN
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<AsnResult> {
        let reader = get_asn_reader()?;
        let lookup = reader.lookup(ip).ok()?;
        let record: GeoAsnRecord = lookup.decode().ok().flatten()?;
        let asn = record.autonomous_system_number?;
        let org = record
            .autonomous_system_organization
            .unwrap_or_default();

        let (is_hosting, is_residential, risk_contribution) = classify_asn(asn);

        Some(AsnResult {
            asn,
            org,
            is_hosting,
            is_residential,
            risk_contribution,
        })
    }

    /// Get country for an IP (legacy API — wraps lookup_country)
    pub async fn get_country(&self, ip: IpAddr) -> Option<String> {
        self.lookup_country(ip)
    }

    /// Get country risk contribution for an IP
    pub fn get_country_risk(&self, ip: IpAddr) -> i32 {
        match self.lookup_country(ip) {
            Some(code) => country_risk(&code),
            None => 5, // Unknown country — slight caution
        }
    }

    /// Get ASN risk contribution for an IP
    pub fn get_asn_risk(&self, ip: IpAddr) -> i32 {
        match self.lookup_asn(ip) {
            Some(result) => result.risk_contribution,
            None => 5, // Unknown ASN — slight caution
        }
    }

    /// Block an IP address
    pub async fn block(&self, ip: IpAddr, reason: &str, duration_secs: u64) {
        let expires = if duration_secs > 0 {
            Some(Instant::now() + Duration::from_secs(duration_secs))
        } else {
            None // Permanent
        };

        self.blocklist.put(ip, BlockEntry {
            reason: reason.to_string(),
            expires,
            _created: Instant::now(),
        });

        // Invalidate cache
        self.cache.remove(&ip);
    }

    /// Unblock an IP address
    pub async fn unblock(&self, ip: IpAddr) {
        self.blocklist.remove(&ip);
        self.cache.remove(&ip);
    }

    /// Add IPs to Tor exit list
    pub fn add_tor_exits(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut tor_exits = self.tor_exits.write();
        tor_exits.extend(ips);
    }

    /// Replace Tor exit list (atomic). Usato da hot-reload dopo file change.
    /// Single write lock acquisito una volta — niente race tra clear+extend.
    pub fn replace_tor_exits(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let new_set: HashSet<IpAddr> = ips.into_iter().collect();
        let mut tor_exits = self.tor_exits.write();
        *tor_exits = new_set;
        // Cache invalidation — il cambio TOR list deve riflettersi subito.
        self.cache.clear();
    }

    /// Load TOR exit nodes da file (one IP per line, # comments ok).
    ///
    /// File format compatibile col cron update-tor-exit-nodes.sh che scrive
    /// /opt/zeliai/data/tor-exit-nodes.txt da check.torproject.org:
    ///   - 1 IP per riga (IPv4 o IPv6)
    ///   - linee vuote/whitespace skip
    ///   - linee che iniziano con # skip (commenti header)
    ///   - IP malformati WARN log ma non fail-fast (resilience)
    ///
    /// Returns Ok(count) parsed o Err(io::Error) se file unreadable.
    pub fn load_tor_exits_from_file(&self, path: &str) -> std::io::Result<usize> {
        use std::io::{BufRead, BufReader};
        let f = std::fs::File::open(path)?;
        let reader = BufReader::new(f);
        let mut ips = Vec::new();
        for (lineno, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match trimmed.parse::<IpAddr>() {
                Ok(ip) => ips.push(ip),
                Err(e) => tracing::warn!(
                    path = %path,
                    line = lineno + 1,
                    value = %trimmed,
                    error = %e,
                    "tor-exit-nodes.txt: line skipped (malformed IP)"
                ),
            }
        }
        let count = ips.len();
        self.replace_tor_exits(ips);
        tracing::info!(path = %path, count = count, "TOR exit nodes loaded");
        Ok(count)
    }

    /// Numero TOR exits caricati (per /metrics observability).
    pub fn tor_exits_count(&self) -> usize {
        self.tor_exits.read().len()
    }

    /// Add IPs to proxy list
    pub fn add_proxies(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut proxies = self.proxies.write();
        proxies.extend(ips);
    }

    /// Add IPs to scanner list
    pub fn add_scanners(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut scanners = self.scanners.write();
        scanners.extend(ips);
    }

    /// Clear all threat lists
    pub fn clear_threat_lists(&self) {
        self.tor_exits.write().clear();
        self.proxies.write().clear();
        self.scanners.write().clear();
    }

    /// Get blocklist size
    pub fn blocklist_size(&self) -> usize {
        self.blocklist.len()
    }

    /// Check if IP is blocked
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.blocklist.with_peek(&ip, |o| match o {
            Some(block) => match block.expires {
                Some(expires) => Instant::now() < expires,
                None => true,
            },
            None => false,
        })
    }

    /// Get all blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<(IpAddr, String, Option<Duration>)> {
        let now = Instant::now();
        let mut out = Vec::new();
        self.blocklist.for_each_mut(|ip, block| {
            // Check if expired
            match block.expires {
                Some(expires) if now >= expires => {} // skip espirata
                Some(expires) => out.push((*ip, block.reason.clone(), Some(expires - now))),
                None => out.push((*ip, block.reason.clone(), None)),
            }
        });
        out
    }
}

impl Default for IpIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 🚨 SESSION1/OOM: blocklist e cache (IP-keyed) sono bounded in TEMPO REALE via
    /// ShardedLru. Pre-fix: DashMap senza cap di size (blocklist cresceva coi ban, cache
    /// solo TTL su accesso) → flood di IP distinti = OOM. cap basso via costruzione diretta.
    #[tokio::test]
    async fn blocklist_and_cache_bounded_realtime_under_ip_flood() {
        let cap = 64; // multiplo dei 16 shard → capacity()==cap
        let intel = IpIntelligence {
            blocklist: ShardedLru::new(cap),
            tor_exits: RwLock::new(HashSet::new()),
            proxies: RwLock::new(HashSet::new()),
            scanners: RwLock::new(HashSet::new()),
            cache: ShardedLru::new(cap),
            cache_ttl: Duration::from_secs(300),
        };
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(203, b[1], b[2], b[3]));
            intel.block(ip, "test", 0).await; // popola blocklist
            let _ = intel.check(ip).await; // popola cache
        }
        assert_eq!(intel.blocklist_size(), cap, "blocklist non bounded (got {})", intel.blocklist_size());
        assert_eq!(intel.cache.len(), cap, "cache non bounded (got {})", intel.cache.len());
    }

    #[tokio::test]
    async fn test_clean_ip() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let reputation = intel.check(ip).await;
        assert_eq!(reputation.score, 1.0);
        assert!(!reputation.is_blocked);
        assert!(reputation.threat_type.is_none());
    }

    #[tokio::test]
    async fn test_block_ip() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        intel.block(ip, "Test block", 3600).await;

        let reputation = intel.check(ip).await;
        assert!(reputation.is_blocked);
        assert_eq!(reputation.score, 0.0);
        assert_eq!(reputation.threat_type, Some(ThreatType::KnownAttacker));
    }

    #[tokio::test]
    async fn test_unblock_ip() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        intel.block(ip, "Test block", 0).await;
        assert!(intel.is_blocked(ip));

        intel.unblock(ip).await;
        assert!(!intel.is_blocked(ip));
    }

    #[tokio::test]
    async fn test_tor_detection() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(185, 220, 101, 1));

        intel.add_tor_exits([ip]);

        let reputation = intel.check(ip).await;
        assert_eq!(reputation.threat_type, Some(ThreatType::TorExitNode));
        assert!(reputation.score < 0.5);
    }

    #[test]
    fn test_country_risk() {
        assert_eq!(country_risk("IT"), 0);
        assert_eq!(country_risk("DE"), 0);
        assert_eq!(country_risk("RU"), 15);
        assert_eq!(country_risk("CN"), 15);
        assert_eq!(country_risk("VN"), 5);
        assert_eq!(country_risk("XX"), 3);
    }

    #[test]
    fn test_asn_classification() {
        let (is_hosting, _, risk) = classify_asn(24940); // Hetzner
        assert!(is_hosting);
        assert_eq!(risk, 10);

        let (is_hosting, _, risk) = classify_asn(49981); // Bulletproof
        assert!(is_hosting);
        assert_eq!(risk, 20);

        let (is_hosting, is_residential, risk) = classify_asn(12345); // Unknown
        assert!(!is_hosting);
        assert!(is_residential);
        assert_eq!(risk, 0);
    }

    #[test]
    fn test_graceful_geoip_without_db() {
        // Without GeoIP DB files, lookups should return None gracefully
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        // Country lookup without DB should return None (not panic)
        let country = intel.lookup_country(ip);
        // Can be None or Some depending on whether test env has GeoIP DB
        let _ = country;
    }
}
