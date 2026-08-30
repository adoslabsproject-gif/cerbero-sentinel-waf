//! Adaptive Rate Limiter with Sliding Window Algorithm
//!
//! Features:
//! - Sliding window for smooth rate limiting
//! - Per-IP tracking with automatic cleanup
//! - Configurable limits and windows
//! - Bounded memory: hard cap on tracked IPs + last-seen eviction (anti IP-rotation DoS)
//!
//! Correctness notes (audit 2026-06-20, fix C1–C4):
//! - C1: `window_start` is now advanced through the DashMap `RefMut` (real interior
//!   mutability) so limiting persists ACROSS windows — previously it was frozen and the
//!   limiter stopped limiting after the first window.
//! - C2: `max_entries` hard cap + eviction → an attacker rotating IPs (IPv6) can no
//!   longer grow the map until OOM.
//! - C3: eviction is by `last_seen` (last access), not by a frozen first-seen timestamp.
//! - C4: the cleanup mutex is poison-safe (recovers instead of panicking).

use sentinel_core::sharded_lru::ShardedLru;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Default hard cap on the number of tracked IPs (bounds memory under IP-rotation DoS).
const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is rate limited
    pub is_limited: bool,
    /// Current request count in window
    pub current_count: u64,
    /// Maximum allowed requests
    pub max_requests: u64,
    /// Ratio of current usage (0.0 - 1.0)
    pub usage_ratio: f64,
    /// Seconds until rate limit resets
    pub reset_in_secs: u64,
    /// Remaining requests in current window
    pub remaining: u64,
}

/// Sliding window entry for an IP.
///
/// Accessed under DashMap's per-shard lock (`RefMut` on the hot path) → plain fields,
/// no atomics needed (the lock provides exclusive access during mutation).
struct WindowEntry {
    /// Request count in current window
    current_count: u64,
    /// Request count in previous window
    previous_count: u64,
    /// Timestamp of current window start (ADVANCED on rotation — see C1)
    window_start: Instant,
    /// Last time this entry was accessed (for last-seen eviction — see C3)
    last_seen: Instant,
}

impl WindowEntry {
    fn new(now: Instant) -> Self {
        Self {
            current_count: 0,
            previous_count: 0,
            window_start: now,
            last_seen: now,
        }
    }
}

/// Adaptive rate limiter using sliding window algorithm
pub struct RateLimiter {
    /// Per-IP rate limit entries. Bound + eviction LRU true-O(1) via ShardedLru
    /// (C2: un attaccante che ruota IP non può crescere la mappa all'OOM; C3:
    /// eviction per last-access). Era DashMap + evict_if_needed batch.
    entries: ShardedLru<IpAddr, WindowEntry>,
    /// Window duration in seconds
    window_secs: u64,
    /// Maximum requests per window
    max_requests: u64,
    /// Last cleanup time. parking_lot::Mutex → non-poisoning by design (C4): un panic
    /// in un'altra sezione non rende panicante ogni richiesta successiva.
    last_cleanup: parking_lot::Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter with the default memory cap.
    pub fn new(window_secs: u64, max_requests: u64) -> Self {
        // window_secs must be ≥ 1: it divides elapsed seconds in the rotation math.
        let window_secs = window_secs.max(1);
        Self {
            entries: ShardedLru::new(DEFAULT_MAX_ENTRIES),
            window_secs,
            max_requests,
            last_cleanup: parking_lot::Mutex::new(Instant::now()),
        }
    }

    /// Builder: override the hard cap on tracked IPs (ricostruisce la mappa).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.entries = ShardedLru::new(max_entries.max(1));
        self
    }

    /// Check if an IP is rate limited and increment counter
    pub async fn check(&self, ip: IpAddr) -> RateLimitResult {
        self.maybe_cleanup();

        let window_duration = Duration::from_secs(self.window_secs);
        let now = Instant::now();

        // Get-or-create + finestra scorrevole + eviction LRU O(1) se al cap,
        // atomically sotto lock dello shard (C1 window advance, C2/C3 bound+last-seen).
        let (current, previous, elapsed) =
            self.entries.with_entry_mut(ip, || WindowEntry::new(now), |entry| {
                entry.last_seen = now; // C3: track last access
                let mut elapsed = now.duration_since(entry.window_start);
                if elapsed >= window_duration {
                    let windows_passed = elapsed.as_secs() / self.window_secs;
                    if windows_passed >= 2 {
                        // Idle ≥2 finestre → la precedente non contribuisce; reset.
                        entry.previous_count = 0;
                        entry.current_count = 1;
                        entry.window_start = now;
                    } else {
                        // Esattamente una finestra passata → slide.
                        entry.previous_count = entry.current_count;
                        entry.current_count = 1;
                        entry.window_start += window_duration;
                    }
                    elapsed = now.duration_since(entry.window_start);
                } else {
                    entry.current_count += 1;
                }
                (entry.current_count, entry.previous_count, elapsed)
            });

        compute_result(current, previous, elapsed, window_duration, self.max_requests)
    }

    /// Check without incrementing (peek). NO promote della recency.
    pub async fn peek(&self, ip: IpAddr) -> Option<RateLimitResult> {
        let window_duration = Duration::from_secs(self.window_secs);
        let now = Instant::now();
        self.entries.with_peek(&ip, |opt| {
            opt.map(|entry| {
                let elapsed = now.duration_since(entry.window_start);
                compute_result(
                    entry.current_count,
                    entry.previous_count,
                    elapsed,
                    window_duration,
                    self.max_requests,
                )
            })
        })
    }

    /// Reset rate limit for an IP
    pub fn reset(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Periodically cleanup old entries (idle ≥ 2 windows). C4: parking_lot::Mutex non
    /// si avvelena → niente panic a cascata su lock poisoned.
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock();
        let cleanup_interval = Duration::from_secs(self.window_secs * 2);

        if last_cleanup.elapsed() < cleanup_interval {
            return;
        }

        let now = Instant::now();
        *last_cleanup = now;
        drop(last_cleanup);

        // C3: evict by LAST ACCESS, not first-seen. Idle ≥ 2 windows → remove.
        let idle_cutoff = Duration::from_secs(self.window_secs * 2);
        self.entries
            .retain(|_, e| now.duration_since(e.last_seen) < idle_cutoff);
    }

    /// Get current number of tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.entries.len()
    }
}

/// Sliding-window score from current/previous counts + elapsed-in-window. Pure (no lock).
fn compute_result(
    current: u64,
    previous: u64,
    elapsed: Duration,
    window_duration: Duration,
    max_requests: u64,
) -> RateLimitResult {
    let window_progress =
        ((elapsed.as_millis() as f64) / (window_duration.as_millis().max(1) as f64)).min(1.0);
    let weighted_previous = (previous as f64) * (1.0 - window_progress);
    let total_count = (current as f64) + weighted_previous;

    let is_limited = total_count > max_requests as f64;
    let usage_ratio = total_count / max_requests as f64;
    let remaining = if is_limited {
        0
    } else {
        (max_requests as f64 - total_count).max(0.0) as u64
    };
    let reset_in_secs = if elapsed < window_duration {
        (window_duration - elapsed).as_secs()
    } else {
        window_duration.as_secs()
    };

    RateLimitResult {
        is_limited,
        current_count: total_count as u64,
        max_requests,
        usage_ratio: usage_ratio.min(2.0), // Cap at 2x for display
        reset_in_secs,
        remaining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(60, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = limiter.check(ip).await;
        assert!(!result.is_limited);
        assert_eq!(result.current_count, 1);
    }

    #[tokio::test]
    async fn test_rate_limiter_limit_exceeded() {
        let limiter = RateLimiter::new(60, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..5 {
            assert!(!limiter.check(ip).await.is_limited);
        }
        assert!(limiter.check(ip).await.is_limited);
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(60, 5);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        for _ in 0..6 {
            limiter.check(ip1).await;
        }
        assert!(!limiter.check(ip2).await.is_limited);
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(60, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..6 {
            limiter.check(ip).await;
        }
        limiter.reset(ip);
        let result = limiter.check(ip).await;
        assert!(!result.is_limited);
        assert_eq!(result.current_count, 1);
    }

    /// 🚨 C1 REGRESSIONE: il limite DEVE persistere OLTRE la prima finestra.
    /// Pre-fix (window_start congelato) ogni richiesta post-finestra-1 resettava il
    /// contatore → mai limitato. Usa window=1s + sleep per attraversare il confine.
    #[tokio::test]
    async fn test_rate_limiter_persists_across_windows() {
        let limiter = RateLimiter::new(1, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Finestra 1: esaurisci.
        for _ in 0..6 {
            limiter.check(ip).await;
        }
        // Attraversa il confine di finestra (rotazione).
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Finestra 2: una raffica DEVE tornare a essere limitata (col bug: mai).
        let mut limited_again = false;
        for _ in 0..12 {
            if limiter.check(ip).await.is_limited {
                limited_again = true;
                break;
            }
        }
        assert!(limited_again, "C1: il rate limiter non limita più dopo la prima finestra");
    }

    /// 🚨 C2 REGRESSIONE: con il cap, una rotazione di IP non fa crescere la mappa
    /// all'infinito (anti-OOM). Pre-fix: nessun cap → entries illimitate.
    #[tokio::test]
    async fn test_rate_limiter_memory_bounded_under_ip_rotation() {
        let cap = 50;
        let limiter = RateLimiter::new(60, 5).with_max_entries(cap);
        // 500 IP distinti (simula rotazione IPv6).
        for i in 0..500u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, i));
            limiter.check(ip).await;
        }
        assert!(
            limiter.tracked_ips() <= cap,
            "C2: la mappa non è limitata ({} > {})",
            limiter.tracked_ips(),
            cap
        );
    }
}
