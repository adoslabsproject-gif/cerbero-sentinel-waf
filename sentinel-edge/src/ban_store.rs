//! Ban Store — SQLite-backed IP ban persistence with optional nftables integration
//!
//! Two-level architecture:
//! 1. In-memory DashMap for real-time decisions (< 1ms lookup)
//! 2. SQLite for persistence (survives restarts, handles 100k+ bans efficiently)
//! 3. Optional: nftables export for kernel-level packet dropping
//!
//! When nftables is enabled, banned IPs are added to an nftables set.
//! The kernel drops packets BEFORE they reach SENTINEL — zero CPU overhead.

use dashmap::DashMap;
use rusqlite::Connection;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Ban entry stored in memory
#[derive(Debug, Clone)]
pub struct BanEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub created: Instant,
    pub expires: Option<Instant>,
    pub created_epoch: u64,
    pub expires_epoch: Option<u64>,
    pub ban_count: u32,
}

/// Ban store configuration
pub struct BanStoreConfig {
    /// Path to SQLite database file
    pub db_path: String,
    /// Enable nftables integration (requires root)
    pub nftables_enabled: bool,
    /// nftables set name for banned IPs
    pub nftables_set: String,
    /// nftables table name
    pub nftables_table: String,
}

impl Default for BanStoreConfig {
    fn default() -> Self {
        Self {
            db_path: std::env::var("SENTINEL_BANS_DB")
                .unwrap_or_else(|_| "./data/sentinel-bans.db".to_string()),
            nftables_enabled: std::env::var("SENTINEL_NFTABLES").unwrap_or_default() == "true",
            nftables_set: "sentinel_banned".to_string(),
            nftables_table: "sentinel".to_string(),
        }
    }
}

/// Two-level ban store: in-memory + SQLite + optional nftables
pub struct BanStore {
    /// Fast in-memory lookup
    memory: DashMap<IpAddr, BanEntry>,
    /// Persistent SQLite storage
    db: Arc<Mutex<Connection>>,
    /// Configuration
    config: BanStoreConfig,
}

impl BanStore {
    /// Create new ban store. Creates SQLite database if it doesn't exist.
    pub fn new(config: BanStoreConfig) -> Self {
        // Ensure data directory exists
        if let Some(parent) = Path::new(&config.db_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(&config.db_path)
            .expect("Failed to open SQLite ban database");

        // Create table with WAL mode for concurrent reads
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                created_epoch INTEGER NOT NULL,
                expires_epoch INTEGER,
                ban_count INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_epoch);
        ").expect("Failed to initialize ban database");

        let store = Self {
            memory: DashMap::new(),
            db: Arc::new(Mutex::new(conn)),
            config,
        };

        // Load active bans from SQLite into memory
        store.load_from_db();

        // Setup nftables if enabled
        if store.config.nftables_enabled {
            store.setup_nftables();
        }

        store
    }

    /// Load active (non-expired) bans from SQLite into memory
    fn load_from_db(&self) {
        let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let now = Instant::now();

        let db = self.db.lock().unwrap();

        // Clean expired bans from DB
        let _ = db.execute(
            "DELETE FROM bans WHERE expires_epoch IS NOT NULL AND expires_epoch < ?1",
            [now_epoch as i64],
        );

        // Load active bans
        let mut stmt = db.prepare(
            "SELECT ip, reason, created_epoch, expires_epoch, ban_count FROM bans"
        ).unwrap();

        let bans = stmt.query_map([], |row| {
            let ip_str: String = row.get(0)?;
            let reason: String = row.get(1)?;
            let created_epoch: u64 = row.get::<_, i64>(2)? as u64;
            let expires_epoch: Option<u64> = row.get::<_, Option<i64>>(3)?.map(|v| v as u64);
            let ban_count: u32 = row.get::<_, i32>(4)? as u32;
            Ok((ip_str, reason, created_epoch, expires_epoch, ban_count))
        }).unwrap();

        let mut count = 0;
        for ban in bans.flatten() {
            let (ip_str, reason, created_epoch, expires_epoch, ban_count) = ban;
            let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };

            let expires = expires_epoch.map(|e| {
                if e > now_epoch {
                    now + Duration::from_secs(e - now_epoch)
                } else {
                    now
                }
            });

            self.memory.insert(ip, BanEntry {
                ip,
                reason,
                created: now,
                expires,
                created_epoch,
                expires_epoch,
                ban_count,
            });
            count += 1;
        }

        if count > 0 {
            tracing::info!(count = count, "Loaded IP bans from database");
        }
    }

    /// Check if an IP is banned (< 1ms — memory only)
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(entry) = self.memory.get(ip) {
            if let Some(expires) = entry.expires {
                if Instant::now() >= expires {
                    // Expired — remove
                    drop(entry);
                    self.memory.remove(ip);
                    self.remove_from_db(ip);
                    return false;
                }
            }
            return true;
        }
        false
    }

    /// Get ban entry if exists
    pub fn get_ban(&self, ip: &IpAddr) -> Option<BanEntry> {
        self.memory.get(ip).map(|e| e.clone())
    }

    /// Ban an IP address — writes to memory + SQLite + optional nftables
    pub fn ban(&self, ip: IpAddr, reason: &str, duration_secs: u64) {
        let now = Instant::now();
        let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let (expires, expires_epoch) = if duration_secs > 0 {
            (Some(now + Duration::from_secs(duration_secs)), Some(now_epoch + duration_secs))
        } else {
            (None, None) // Permanent
        };

        // Check if already banned (increment count)
        let ban_count = self.memory.get(&ip)
            .map(|e| e.ban_count + 1)
            .unwrap_or(1);

        let entry = BanEntry {
            ip,
            reason: reason.to_string(),
            created: now,
            expires,
            created_epoch: now_epoch,
            expires_epoch,
            ban_count,
        };

        // 1. Memory
        self.memory.insert(ip, entry);

        // 2. SQLite
        let db = self.db.lock().unwrap();
        let _ = db.execute(
            "INSERT OR REPLACE INTO bans (ip, reason, created_epoch, expires_epoch, ban_count) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                ip.to_string(),
                reason,
                now_epoch as i64,
                expires_epoch.map(|e| e as i64),
                ban_count as i32,
            ],
        );

        // 3. nftables (kernel-level blocking)
        if self.config.nftables_enabled {
            self.nft_add_ip(&ip);
        }

        tracing::warn!(
            ip = %ip,
            reason = reason,
            duration_secs = duration_secs,
            ban_count = ban_count,
            "IP banned"
        );
    }

    /// Unban an IP address
    pub fn unban(&self, ip: &IpAddr) {
        self.memory.remove(ip);
        self.remove_from_db(ip);

        if self.config.nftables_enabled {
            self.nft_remove_ip(ip);
        }

        tracing::info!(ip = %ip, "IP unbanned");
    }

    fn remove_from_db(&self, ip: &IpAddr) {
        let db = self.db.lock().unwrap();
        let _ = db.execute("DELETE FROM bans WHERE ip = ?1", [ip.to_string()]);
    }

    /// Get all active bans
    pub fn list_bans(&self) -> Vec<BanEntry> {
        let now = Instant::now();
        self.memory.iter()
            .filter(|e| {
                if let Some(expires) = e.expires {
                    now < expires
                } else {
                    true
                }
            })
            .map(|e| e.clone())
            .collect()
    }

    /// Get ban count
    pub fn count(&self) -> usize {
        self.memory.len()
    }

    /// Cleanup expired bans (call periodically)
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut expired: Vec<IpAddr> = Vec::new();

        for entry in self.memory.iter() {
            if let Some(expires) = entry.expires {
                if now >= expires {
                    expired.push(*entry.key());
                }
            }
        }

        for ip in &expired {
            self.memory.remove(ip);
            if self.config.nftables_enabled {
                self.nft_remove_ip(ip);
            }
        }

        if !expired.is_empty() {
            // Batch delete from SQLite
            let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let db = self.db.lock().unwrap();
            let _ = db.execute(
                "DELETE FROM bans WHERE expires_epoch IS NOT NULL AND expires_epoch < ?1",
                [now_epoch as i64],
            );
            tracing::info!(count = expired.len(), "Cleaned up expired bans");
        }
    }

    // ── nftables integration ──────────────────────────────────────────

    /// Setup nftables table and set for SENTINEL bans
    fn setup_nftables(&self) {
        let table = &self.config.nftables_table;
        let set = &self.config.nftables_set;

        // Create table + set + drop rule
        let commands = format!(
            "nft add table inet {table} 2>/dev/null; \
             nft add set inet {table} {set} {{ type ipv4_addr \\; flags timeout \\; }} 2>/dev/null; \
             nft add set inet {table} {set}_v6 {{ type ipv6_addr \\; flags timeout \\; }} 2>/dev/null; \
             nft add chain inet {table} input {{ type filter hook input priority -10 \\; policy accept \\; }} 2>/dev/null; \
             nft add rule inet {table} input ip saddr @{set} drop 2>/dev/null; \
             nft add rule inet {table} input ip6 saddr @{set}_v6 drop 2>/dev/null"
        );

        match std::process::Command::new("sh").arg("-c").arg(&commands).status() {
            Ok(status) if status.success() => {
                tracing::info!("nftables integration active — banned IPs dropped at kernel level");

                // Re-add all existing bans to nftables
                for entry in self.memory.iter() {
                    self.nft_add_ip(entry.key());
                }
            }
            Ok(_) => {
                tracing::warn!("nftables setup failed — requires root. Falling back to application-level blocking.");
            }
            Err(e) => {
                tracing::warn!("nftables not available: {} — using application-level blocking", e);
            }
        }
    }

    /// Add IP to nftables banned set
    fn nft_add_ip(&self, ip: &IpAddr) {
        let table = &self.config.nftables_table;
        let (set, ip_str) = match ip {
            IpAddr::V4(_) => (&self.config.nftables_set, ip.to_string()),
            IpAddr::V6(_) => (&format!("{}_v6", self.config.nftables_set), ip.to_string()),
        };

        let cmd = format!("nft add element inet {table} {set} {{ {ip_str} }}");
        let _ = std::process::Command::new("sh").arg("-c").arg(&cmd)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    /// Remove IP from nftables banned set
    fn nft_remove_ip(&self, ip: &IpAddr) {
        let table = &self.config.nftables_table;
        let (set, ip_str) = match ip {
            IpAddr::V4(_) => (&self.config.nftables_set, ip.to_string()),
            IpAddr::V6(_) => (&format!("{}_v6", self.config.nftables_set), ip.to_string()),
        };

        let cmd = format!("nft delete element inet {table} {set} {{ {ip_str} }}");
        let _ = std::process::Command::new("sh").arg("-c").arg(&cmd)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use std::sync::atomic::{AtomicU32, Ordering};
    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn test_config() -> BanStoreConfig {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        BanStoreConfig {
            db_path: format!("/tmp/sentinel-test-bans-{}-{}.db", std::process::id(), id),
            nftables_enabled: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_ban_and_check() {
        let config = test_config();
        let store = BanStore::new(config.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(!store.is_banned(&ip));
        store.ban(ip, "test", 3600);
        assert!(store.is_banned(&ip));

        let _ = std::fs::remove_file(&config.db_path);
    }

    #[test]
    fn test_unban() {
        let config = test_config();
        let store = BanStore::new(config.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        store.ban(ip, "test", 0); // permanent
        assert!(store.is_banned(&ip));

        store.unban(&ip);
        assert!(!store.is_banned(&ip));

        let _ = std::fs::remove_file(&config.db_path);
    }

    #[test]
    fn test_persistence() {
        let config = test_config();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));

        // Create store, ban IP
        {
            let store = BanStore::new(config.clone());
            store.ban(ip, "persistent test", 86400);
            assert!(store.is_banned(&ip));
        }

        // New store instance — ban should be loaded from SQLite
        {
            let store = BanStore::new(config.clone());
            assert!(store.is_banned(&ip));
            let ban = store.get_ban(&ip).unwrap();
            assert_eq!(ban.reason, "persistent test");
        }

        let _ = std::fs::remove_file(&config.db_path);
    }

    #[test]
    fn test_ban_count_increment() {
        let config = test_config();
        let store = BanStore::new(config.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(11, 22, 33, 44));

        store.ban(ip, "first", 3600);
        assert_eq!(store.get_ban(&ip).unwrap().ban_count, 1);

        store.ban(ip, "second", 7200);
        assert_eq!(store.get_ban(&ip).unwrap().ban_count, 2);

        let _ = std::fs::remove_file(&config.db_path);
    }

    impl Clone for BanStoreConfig {
        fn clone(&self) -> Self {
            Self {
                db_path: self.db_path.clone(),
                nftables_enabled: self.nftables_enabled,
                nftables_set: self.nftables_set.clone(),
                nftables_table: self.nftables_table.clone(),
            }
        }
    }
}
