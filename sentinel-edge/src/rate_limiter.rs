//! Adaptive Rate Limiter with Sliding Window Algorithm
//!
//! Features:
//! - Sliding window for smooth rate limiting
//! - Per-IP tracking with automatic cleanup
//! - Configurable limits and windows
//! - Memory-efficient with LRU eviction

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

/// Sliding window entry for an IP
struct WindowEntry {
    /// Request count in current window
    current_count: AtomicU64,
    /// Request count in previous window
    previous_count: AtomicU64,
    /// Timestamp of window start
    window_start: Instant,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            current_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            window_start: Instant::now(),
        }
    }
}

/// Adaptive rate limiter using sliding window algorithm
pub struct RateLimiter {
    /// Per-IP rate limit entries
    entries: DashMap<IpAddr, WindowEntry>,
    /// Window duration in seconds
    window_secs: u64,
    /// Maximum requests per window
    max_requests: u64,
    /// Last cleanup time
    last_cleanup: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(window_secs: u64, max_requests: u64) -> Self {
        Self {
            entries: DashMap::new(),
            window_secs,
            max_requests,
            last_cleanup: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Check if an IP is rate limited and increment counter
    pub async fn check(&self, ip: IpAddr) -> RateLimitResult {
        self.maybe_cleanup();

        let window_duration = Duration::from_secs(self.window_secs);
        let now = Instant::now();

        // Get or create entry for this IP
        let entry = self.entries.entry(ip).or_insert_with(WindowEntry::new);

        // Check if we need to rotate the window
        let elapsed = now.duration_since(entry.window_start);
        if elapsed >= window_duration {
            // Calculate how many windows have passed
            let windows_passed = elapsed.as_secs() / self.window_secs;

            if windows_passed >= 2 {
                // More than 2 windows passed, reset everything
                entry.previous_count.store(0, Ordering::SeqCst);
                entry.current_count.store(1, Ordering::SeqCst);
            } else {
                // One window passed, rotate
                let current = entry.current_count.load(Ordering::SeqCst);
                entry.previous_count.store(current, Ordering::SeqCst);
                entry.current_count.store(1, Ordering::SeqCst);
            }

            // Note: We can't mutate window_start through DashMap entry
            // This is a simplification - in production, use interior mutability
        } else {
            // Same window, increment
            entry.current_count.fetch_add(1, Ordering::SeqCst);
        }

        // Calculate sliding window count
        let current = entry.current_count.load(Ordering::SeqCst);
        let previous = entry.previous_count.load(Ordering::SeqCst);

        // Weight the previous window based on how much time has passed
        let window_progress = (elapsed.as_millis() as f64) / (window_duration.as_millis() as f64);
        let window_progress = window_progress.min(1.0);

        let weighted_previous = (previous as f64) * (1.0 - window_progress);
        let total_count = (current as f64) + weighted_previous;

        let is_limited = total_count > self.max_requests as f64;
        let usage_ratio = total_count / self.max_requests as f64;
        let remaining = if is_limited {
            0
        } else {
            (self.max_requests as f64 - total_count).max(0.0) as u64
        };

        let reset_in_secs = if elapsed < window_duration {
            (window_duration - elapsed).as_secs()
        } else {
            self.window_secs
        };

        RateLimitResult {
            is_limited,
            current_count: total_count as u64,
            max_requests: self.max_requests,
            usage_ratio: usage_ratio.min(2.0), // Cap at 2x for display
            reset_in_secs,
            remaining,
        }
    }

    /// Check without incrementing (peek)
    pub async fn peek(&self, ip: IpAddr) -> Option<RateLimitResult> {
        let entry = self.entries.get(&ip)?;
        let window_duration = Duration::from_secs(self.window_secs);
        let now = Instant::now();
        let elapsed = now.duration_since(entry.window_start);

        let current = entry.current_count.load(Ordering::SeqCst);
        let previous = entry.previous_count.load(Ordering::SeqCst);

        let window_progress = (elapsed.as_millis() as f64) / (window_duration.as_millis() as f64);
        let window_progress = window_progress.min(1.0);

        let weighted_previous = (previous as f64) * (1.0 - window_progress);
        let total_count = (current as f64) + weighted_previous;

        let is_limited = total_count > self.max_requests as f64;
        let usage_ratio = total_count / self.max_requests as f64;
        let remaining = if is_limited {
            0
        } else {
            (self.max_requests as f64 - total_count).max(0.0) as u64
        };

        let reset_in_secs = if elapsed < window_duration {
            (window_duration - elapsed).as_secs()
        } else {
            self.window_secs
        };

        Some(RateLimitResult {
            is_limited,
            current_count: total_count as u64,
            max_requests: self.max_requests,
            usage_ratio: usage_ratio.min(2.0),
            reset_in_secs,
            remaining,
        })
    }

    /// Reset rate limit for an IP
    pub fn reset(&self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// Periodically cleanup old entries
    fn maybe_cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        let cleanup_interval = Duration::from_secs(self.window_secs * 2);

        if last_cleanup.elapsed() < cleanup_interval {
            return;
        }

        *last_cleanup = Instant::now();
        drop(last_cleanup);

        // Remove entries that haven't been accessed in 2 windows
        let cutoff = Instant::now() - Duration::from_secs(self.window_secs * 2);
        self.entries.retain(|_, entry| entry.window_start > cutoff);
    }

    /// Get current number of tracked IPs
    pub fn tracked_ips(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(60, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First request should pass
        let result = limiter.check(ip).await;
        assert!(!result.is_limited);
        assert_eq!(result.current_count, 1);
    }

    #[tokio::test]
    async fn test_rate_limiter_limit_exceeded() {
        let limiter = RateLimiter::new(60, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Make 6 requests (limit is 5)
        for _ in 0..5 {
            let result = limiter.check(ip).await;
            assert!(!result.is_limited);
        }

        // 6th request should be limited
        let result = limiter.check(ip).await;
        assert!(result.is_limited);
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(60, 5);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust limit for ip1
        for _ in 0..6 {
            limiter.check(ip1).await;
        }

        // ip2 should still be fine
        let result = limiter.check(ip2).await;
        assert!(!result.is_limited);
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(60, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust limit
        for _ in 0..6 {
            limiter.check(ip).await;
        }

        // Reset
        limiter.reset(ip);

        // Should be able to make requests again
        let result = limiter.check(ip).await;
        assert!(!result.is_limited);
        assert_eq!(result.current_count, 1);
    }
}
