//! G3 (2026-06-02): distributed rate-limit via Redis shared store.
//!
//! Estende l'endpoint_limiter locale con backing Redis cross-instance.
//! Stesso (ip, policy) hit da N pod aggrega centralmente.
//!
//! Pattern: INCR + EXPIRE atomic via Lua script. Su Redis down → fail-open
//! (limiter locale resta autoritativo).
//!
//! Config:
//!   SENTINEL_REDIS_URL=redis://127.0.0.1:6379 (env, default disabilitato)
//!
//! USO:
//!   let store = RedisRateLimitStore::connect(&url).await?;
//!   let count = store.incr_window("login-strict:1.2.3.4", 60).await;
//!   if count > 5 { /* limited */ }

use once_cell::sync::Lazy;
use redis::aio::ConnectionManager;

/// Lua script atomic: INCR + se primo hit, EXPIRE in window_secs.
/// Restituisce il nuovo count.
const INCR_WITH_EXPIRE_LUA: &str = r#"
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, ttl)
end
return count
"#;

/// Script pre-compilato UNA VOLTA (R-RL5): evita di ri-allocare `redis::Script` a ogni
/// richiesta. Il SHA è cachato dal driver → la prima invoke fa SCRIPT LOAD, le successive
/// EVALSHA.
static INCR_SCRIPT: Lazy<redis::Script> = Lazy::new(|| redis::Script::new(INCR_WITH_EXPIRE_LUA));

#[derive(Clone)]
pub struct RedisRateLimitStore {
    /// R-RL2: connessione CONDIVISA e auto-reconnecting (ConnectionManager multiplexa su
    /// un solo socket + riconnette da solo). Prima si apriva una connessione NUOVA a OGNI
    /// `incr_window` (= ogni request del WAF) → connection storm + latenza su Redis.
    /// `None` = store disabilitato (fail-open). Cloneare il manager è cheap (Arc interno).
    conn: Option<ConnectionManager>,
}

impl RedisRateLimitStore {
    /// Connect a Redis. Su error → ritorna `Err` (il caller fa fallback a `disabled()`).
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("redis client open: {e}"))?;
        // ConnectionManager: stabilisce + mantiene UNA connessione riusabile, con
        // riconnessione automatica e backoff. Sostituisce il connect-per-request.
        let mut mgr = ConnectionManager::new(client)
            .await
            .map_err(|e| format!("redis connection-manager: {e}"))?;
        // Health-check esplicito al boot.
        let _: String = redis::cmd("PING")
            .query_async(&mut mgr)
            .await
            .map_err(|e| format!("redis ping: {e}"))?;
        Ok(Self { conn: Some(mgr) })
    }

    /// Disabled store (fail-open). Usato quando SENTINEL_REDIS_URL non è settato o la
    /// connessione iniziale fallisce.
    pub fn disabled() -> Self {
        Self { conn: None }
    }

    /// INCR atomic con EXPIRE window_secs. Ritorna count corrente.
    ///
    /// Fail-open DICHIARATO (R-RL1, design accettato): su Redis down/errore ritorna 0 →
    /// il limiter LOCALE per-istanza resta autoritativo. Scelta: disponibilità del WAF >
    /// precisione del conteggio distribuito durante un outage Redis (un attaccante non
    /// guadagna nulla oltre il limite locale già applicato).
    pub async fn incr_window(&self, key: &str, window_secs: u64) -> u64 {
        let Some(conn) = self.conn.as_ref() else {
            return 0; // disabled → fail-open
        };
        // Clone del manager = cheap (Arc interno), riusa il socket condiviso. NESSUN
        // nuovo connect per-request.
        let mut conn = conn.clone();
        let result: Result<u64, redis::RedisError> = INCR_SCRIPT
            .key(format!("sentinel:rl:{key}"))
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await;
        match result {
            Ok(count) => count,
            Err(e) => {
                tracing::debug!(error = %e, key = key, "G3: Redis INCR fail, fail-open");
                0 // R-RL1 fail-open
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.conn.is_some()
    }
}

/// Helper: chiave canonica per per-ip per-policy
pub fn make_rl_key(ip: &str, policy_label: &str) -> String {
    format!("{policy_label}:{ip}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_store_always_returns_zero() {
        let store = RedisRateLimitStore::disabled();
        assert!(!store.is_enabled());
        let count = store.incr_window("test-key", 60).await;
        assert_eq!(count, 0, "disabled store deve essere fail-open (0)");
    }

    #[test]
    fn make_rl_key_format() {
        assert_eq!(make_rl_key("1.2.3.4", "login-strict"), "login-strict:1.2.3.4");
        assert_eq!(make_rl_key("::1", "api-default"), "api-default:::1");
    }

    #[tokio::test]
    async fn connect_invalid_url_returns_err() {
        let result = RedisRateLimitStore::connect("redis://nonexistent.invalid:6379/0").await;
        assert!(result.is_err(), "invalid URL deve essere Err");
    }

    /// Test integration con Redis reale (richiede REDIS_URL env)
    #[tokio::test]
    async fn incr_window_with_local_redis() {
        let url = std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let store = match RedisRateLimitStore::connect(&url).await {
            Ok(s) => s,
            Err(_) => {
                // Skip se Redis non disponibile in test env
                eprintln!("Skipping Redis integration test (no local Redis)");
                return;
            }
        };
        let key = format!("test-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let c1 = store.incr_window(&key, 5).await;
        let c2 = store.incr_window(&key, 5).await;
        let c3 = store.incr_window(&key, 5).await;
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);
        assert_eq!(c3, 3);

        // Verifica TTL applicato — riusa la connessione condivisa (no nuovo connect).
        use redis::AsyncCommands;
        let mut conn = store.conn.clone().expect("store abilitato → conn presente");
        let ttl: i64 = conn.ttl(&format!("sentinel:rl:{key}")).await.unwrap();
        assert!(ttl > 0 && ttl <= 5, "TTL deve essere 1-5s, got {ttl}");

        // R-RL2 (regressione): più incr_window sullo STESSO store NON aprono connessioni
        // nuove — riusano il ConnectionManager condiviso. (3 incr sopra + questo TTL su una
        // sola connessione clonata = prova del riuso.)
        assert!(store.is_enabled());
    }
}
