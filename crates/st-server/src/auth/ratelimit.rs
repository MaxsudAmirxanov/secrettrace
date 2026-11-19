//! In-process fixed-window rate limiter for authentication endpoints.
//!
//! Complements the per-account lockout stored in the database: the limiter slows
//! down spraying across many usernames from one IP and keeps argon2 work bounded.
//! State is per process; with several API replicas the effective limit scales with
//! the replica count (acceptable for the MVP single-node deployment).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PRUNE_THRESHOLD: usize = 10_000;

#[derive(Debug)]
pub struct RateLimiter {
    max: u32,
    window: Duration,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, buckets: Mutex::new(HashMap::new()) }
    }

    /// Count one attempt for `key`; `false` when the limit is exceeded.
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() >= PRUNE_THRESHOLD {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.max
    }
}

/// Limiters used by the auth routes.
#[derive(Debug)]
pub struct AuthLimiters {
    pub login_per_ip: RateLimiter,
    pub login_per_user: RateLimiter,
    pub mfa_per_user: RateLimiter,
}

impl Default for AuthLimiters {
    fn default() -> Self {
        let minute = Duration::from_secs(60);
        Self {
            login_per_ip: RateLimiter::new(20, minute),
            login_per_user: RateLimiter::new(10, minute),
            mfa_per_user: RateLimiter::new(5, minute),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_within_window_and_resets() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        assert!(!rl.check_at("a", t0));
        assert!(rl.check_at("b", t0), "keys are independent");
        assert!(rl.check_at("a", t0 + Duration::from_secs(61)), "window resets");
    }
}
