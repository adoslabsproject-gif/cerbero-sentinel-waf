//! IP Intelligence Module
//!
//! Provides IP reputation scoring and threat detection:
//! - Known attacker detection
//! - Tor exit node detection
//! - Proxy/VPN detection
//! - Botnet detection
//! - Geographic lookup (MaxMind GeoLite2)
//! - Ban persistence (survives restarts)

use dashmap::DashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::path::Path;

/// Types of threats associated with an IP
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreatType {
    KnownAttacker,
    TorExitNode,
    Proxy,
    Scanner,
    Botnet,
}

/// IP reputation information
#[derive(Debug, Clone)]
pub struct IpReputation {
    pub score: f64,
    pub threat_type: Option<ThreatType>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub is_datacenter: bool,
    pub is_blocked: bool,
    pub block_reason: Option<String>,
    pub block_expires: Option<Instant>,
}

impl Default for IpReputation {
    fn default() -> Self {
        Self {
            score: 1.0,
            threat_type: None,
            country: None,
            asn: None,
            is_datacenter: false,
            is_blocked: false,
            block_reason: None,
            block_expires: None,
        }
    }
}

/// Persistent ban entry (serializable)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistentBan {
    ip: String,
    reason: String,
    created_epoch: u64,
    expires_epoch: Option<u64>, // None = permanent
}

/// Block entry for an IP (in-memory)
struct BlockEntry {
    reason: String,
    expires: Option<Instant>,
    _created: Instant,
    created_epoch: u64,
    expires_epoch: Option<u64>,
}

/// IP Intelligence service
pub struct IpIntelligence {
    blocklist: DashMap<IpAddr, BlockEntry>,
    tor_exits: RwLock<HashSet<IpAddr>>,
    proxies: RwLock<HashSet<IpAddr>>,
    scanners: RwLock<HashSet<IpAddr>>,
    cache: DashMap<IpAddr, (IpReputation, Instant)>,
    cache_ttl: Duration,
    /// Path to GeoLite2-City.mmdb (None if unavailable)
    geoip_city: Option<maxminddb::Reader<Vec<u8>>>,
    /// Path to GeoLite2-ASN.mmdb (None if unavailable)
    geoip_asn: Option<maxminddb::Reader<Vec<u8>>>,
    /// Path to persist bans
    bans_file: Option<String>,
}

/// Known datacenter ASNs (partial list — major cloud providers)
const DATACENTER_ASNS: &[u32] = &[
    13335,  // Cloudflare
    16509,  // Amazon AWS
    14618,  // Amazon AWS
    15169,  // Google Cloud
    8075,   // Microsoft Azure
    20940,  // Akamai
    54113,  // Fastly
    13238,  // Yandex
    45090,  // Tencent Cloud
    37963,  // Alibaba Cloud
    16276,  // OVH
    24940,  // Hetzner
    63949,  // Linode/Akamai
    14061,  // DigitalOcean
    46844,  // Sharktech
    55286,  // ServerCentral
    32244,  // Liquid Web
];

impl IpIntelligence {
    /// Create a new IP Intelligence service.
    /// Loads GeoIP databases if SENTINEL_GEOIP_PATH is set.
    /// Loads persisted bans if SENTINEL_BANS_FILE is set.
    pub fn new() -> Self {
        let geoip_path = std::env::var("SENTINEL_GEOIP_PATH")
            .unwrap_or_else(|_| "./data/geoip".to_string());
        let bans_path = std::env::var("SENTINEL_BANS_FILE")
            .unwrap_or_else(|_| "./data/sentinel-bans.json".to_string());

        let geoip_city = Self::load_mmdb(&format!("{}/GeoLite2-City.mmdb", geoip_path));
        let geoip_asn = Self::load_mmdb(&format!("{}/GeoLite2-ASN.mmdb", geoip_path));

        if geoip_city.is_some() {
            tracing::info!("GeoIP City database loaded");
        } else {
            tracing::warn!("GeoIP City database not found at {}/GeoLite2-City.mmdb — country detection disabled", geoip_path);
        }
        if geoip_asn.is_some() {
            tracing::info!("GeoIP ASN database loaded");
        } else {
            tracing::warn!("GeoIP ASN database not found — datacenter detection disabled");
        }

        let mut intel = Self {
            blocklist: DashMap::new(),
            tor_exits: RwLock::new(HashSet::new()),
            proxies: RwLock::new(HashSet::new()),
            scanners: RwLock::new(HashSet::new()),
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(300),
            geoip_city,
            geoip_asn,
            bans_file: Some(bans_path.clone()),
        };

        // Load persisted bans
        intel.load_bans();

        intel
    }

    fn load_mmdb(path: &str) -> Option<maxminddb::Reader<Vec<u8>>> {
        if !Path::new(path).exists() { return None; }
        match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => Some(reader),
            Err(e) => {
                tracing::error!("Failed to load GeoIP database {}: {}", path, e);
                None
            }
        }
    }

    /// Check IP reputation
    pub async fn check(&self, ip: IpAddr) -> IpReputation {
        // Check cache first
        if let Some(entry) = self.cache.get(&ip) {
            if entry.1.elapsed() < self.cache_ttl {
                return entry.0.clone();
            }
        }

        let mut reputation = IpReputation::default();

        // GeoIP lookup
        if let Some(ref reader) = self.geoip_city {
            if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                reputation.country = city.country
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string());
            }
        }

        if let Some(ref reader) = self.geoip_asn {
            if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                reputation.asn = asn.autonomous_system_number;
                if let Some(asn_num) = reputation.asn {
                    reputation.is_datacenter = DATACENTER_ASNS.contains(&asn_num);
                }
            }
        }

        // Check blocklist
        if let Some(block) = self.blocklist.get(&ip) {
            if let Some(expires) = block.expires {
                if Instant::now() >= expires {
                    drop(block);
                    self.blocklist.remove(&ip);
                } else {
                    reputation.is_blocked = true;
                    reputation.block_reason = Some(block.reason.clone());
                    reputation.block_expires = Some(expires);
                    reputation.score = 0.0;
                    reputation.threat_type = Some(ThreatType::KnownAttacker);
                }
            } else {
                reputation.is_blocked = true;
                reputation.block_reason = Some(block.reason.clone());
                reputation.score = 0.0;
                reputation.threat_type = Some(ThreatType::KnownAttacker);
            }
        }

        // Check threat lists
        if !reputation.is_blocked {
            let tor_exits = self.tor_exits.read().unwrap();
            if tor_exits.contains(&ip) {
                reputation.threat_type = Some(ThreatType::TorExitNode);
                reputation.score = 0.3;
            }
        }

        if !reputation.is_blocked && reputation.threat_type.is_none() {
            let proxies = self.proxies.read().unwrap();
            if proxies.contains(&ip) {
                reputation.threat_type = Some(ThreatType::Proxy);
                reputation.score = 0.5;
            }
        }

        if !reputation.is_blocked && reputation.threat_type.is_none() {
            let scanners = self.scanners.read().unwrap();
            if scanners.contains(&ip) {
                reputation.threat_type = Some(ThreatType::Scanner);
                reputation.score = 0.2;
            }
        }

        // Datacenter IPs get a slight risk bump
        if reputation.is_datacenter && reputation.score > 0.7 {
            reputation.score = 0.7;
        }

        self.cache.insert(ip, (reputation.clone(), Instant::now()));
        reputation
    }

    /// Block an IP address — persisted to disk
    pub async fn block(&self, ip: IpAddr, reason: &str, duration_secs: u64) {
        let now = Instant::now();
        let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let (expires, expires_epoch) = if duration_secs > 0 {
            (Some(now + Duration::from_secs(duration_secs)), Some(now_epoch + duration_secs))
        } else {
            (None, None)
        };

        self.blocklist.insert(ip, BlockEntry {
            reason: reason.to_string(),
            expires,
            _created: now,
            created_epoch: now_epoch,
            expires_epoch,
        });

        self.cache.remove(&ip);
        self.persist_bans();

        tracing::warn!(
            ip = %ip,
            reason = reason,
            duration_secs = duration_secs,
            "IP banned"
        );
    }

    /// Unblock an IP address
    pub async fn unblock(&self, ip: IpAddr) {
        self.blocklist.remove(&ip);
        self.cache.remove(&ip);
        self.persist_bans();
    }

    /// Persist bans to disk (JSON file)
    fn persist_bans(&self) {
        let Some(ref path) = self.bans_file else { return };
        let bans: Vec<PersistentBan> = self.blocklist.iter().map(|entry| {
            let ip = entry.key();
            let block = entry.value();
            PersistentBan {
                ip: ip.to_string(),
                reason: block.reason.clone(),
                created_epoch: block.created_epoch,
                expires_epoch: block.expires_epoch,
            }
        }).collect();

        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&bans) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Load bans from disk
    fn load_bans(&mut self) {
        let Some(ref path) = self.bans_file else { return };
        let Ok(data) = std::fs::read_to_string(path) else { return };
        let Ok(bans) = serde_json::from_str::<Vec<PersistentBan>>(&data) else { return };

        let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let now = Instant::now();
        let mut loaded = 0;

        for ban in bans {
            // Skip expired bans
            if let Some(expires_epoch) = ban.expires_epoch {
                if now_epoch >= expires_epoch { continue; }
            }

            let Ok(ip) = ban.ip.parse::<IpAddr>() else { continue };
            let expires = ban.expires_epoch.map(|e| {
                if e > now_epoch {
                    now + Duration::from_secs(e - now_epoch)
                } else {
                    now // already expired
                }
            });

            self.blocklist.insert(ip, BlockEntry {
                reason: ban.reason,
                expires,
                _created: now,
                created_epoch: ban.created_epoch,
                expires_epoch: ban.expires_epoch,
            });
            loaded += 1;
        }

        if loaded > 0 {
            tracing::info!(count = loaded, "Loaded persisted IP bans");
        }
    }

    /// Get country for an IP (requires GeoLite2-City.mmdb)
    pub async fn get_country(&self, ip: IpAddr) -> Option<String> {
        if let Some(ref reader) = self.geoip_city {
            if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                return city.country.and_then(|c| c.iso_code).map(|s| s.to_string());
            }
        }
        None
    }

    /// Get ASN for an IP (requires GeoLite2-ASN.mmdb)
    pub async fn get_asn(&self, ip: IpAddr) -> Option<(u32, bool)> {
        if let Some(ref reader) = self.geoip_asn {
            if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                if let Some(asn_num) = asn.autonomous_system_number {
                    return Some((asn_num, DATACENTER_ASNS.contains(&asn_num)));
                }
            }
        }
        None
    }

    pub fn add_tor_exits(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut tor_exits = self.tor_exits.write().unwrap();
        tor_exits.extend(ips);
    }

    pub fn add_proxies(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut proxies = self.proxies.write().unwrap();
        proxies.extend(ips);
    }

    pub fn add_scanners(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut scanners = self.scanners.write().unwrap();
        scanners.extend(ips);
    }

    pub fn clear_threat_lists(&self) {
        self.tor_exits.write().unwrap().clear();
        self.proxies.write().unwrap().clear();
        self.scanners.write().unwrap().clear();
    }

    pub fn blocklist_size(&self) -> usize {
        self.blocklist.len()
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if let Some(block) = self.blocklist.get(&ip) {
            if let Some(expires) = block.expires {
                return Instant::now() < expires;
            }
            return true;
        }
        false
    }

    pub fn get_blocked_ips(&self) -> Vec<(IpAddr, String, Option<Duration>)> {
        let now = Instant::now();
        self.blocklist
            .iter()
            .filter_map(|entry| {
                let ip = *entry.key();
                let block = entry.value();
                if let Some(expires) = block.expires {
                    if now >= expires { return None; }
                    Some((ip, block.reason.clone(), Some(expires - now)))
                } else {
                    Some((ip, block.reason.clone(), None))
                }
            })
            .collect()
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

    #[tokio::test]
    async fn test_clean_ip() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let reputation = intel.check(ip).await;
        assert_eq!(reputation.score, 1.0);
        assert!(!reputation.is_blocked);
    }

    #[tokio::test]
    async fn test_block_ip() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        intel.block(ip, "Test block", 3600).await;
        let reputation = intel.check(ip).await;
        assert!(reputation.is_blocked);
        assert_eq!(reputation.score, 0.0);
    }

    #[tokio::test]
    async fn test_tor_detection() {
        let intel = IpIntelligence::new();
        let ip = IpAddr::V4(Ipv4Addr::new(185, 220, 101, 1));
        intel.add_tor_exits([ip]);
        let reputation = intel.check(ip).await;
        assert_eq!(reputation.threat_type, Some(ThreatType::TorExitNode));
    }
}
