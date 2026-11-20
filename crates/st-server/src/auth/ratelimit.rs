//! In-process fixed-window rate limiter for authentication and ingest endpoints.
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
        let entry = self.bucket(&mut buckets, key, now);
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.max
    }

    /// Spend `n` units (e.g. digests) for `key`. Unlike [`RateLimiter::check`], a refused
    /// request consumes nothing, so one oversized batch does not lock the key out.
    pub fn check_n(&self, key: &str, n: u32) -> bool {
        self.check_n_at(key, n, Instant::now())
    }

    fn check_n_at(&self, key: &str, n: u32, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = self.bucket(&mut buckets, key, now);
        match entry.1.checked_add(n) {
            Some(total) if total <= self.max => {
                entry.1 = total;
                true
            }
            _ => false,
        }
    }

    fn bucket<'b>(
        &self,
        buckets: &'b mut HashMap<String, (Instant, u32)>,
        key: &str,
        now: Instant,
    ) -> &'b mut (Instant, u32) {
        if buckets.len() >= PRUNE_THRESHOLD {
            buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = buckets.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry
    }
}

/// Registrations one user may attempt per hour.
pub const SECRET_CREATES_PER_HOUR: u32 = 100;

/// Limiters used by the auth routes and by secret registration.
#[derive(Debug)]
pub struct AuthLimiters {
    pub login_per_ip: RateLimiter,
    pub login_per_user: RateLimiter,
    pub mfa_per_user: RateLimiter,
    /// `POST /secrets` per user: bounds registration as a "is X registered?" oracle.
    pub secret_create_per_user: RateLimiter,
}

impl Default for AuthLimiters {
    fn default() -> Self {
        let minute = Duration::from_secs(60);
        Self {
            login_per_ip: RateLimiter::new(20, minute),
            login_per_user: RateLimiter::new(10, minute),
            mfa_per_user: RateLimiter::new(5, minute),
            secret_create_per_user: RateLimiter::new(SECRET_CREATES_PER_HOUR, Duration::from_secs(3600)),
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

    #[test]
    fn weighted_spending() {
        let rl = RateLimiter::new(100, Duration::from_secs(3600));
        let t0 = Instant::now();
        assert!(rl.check_n_at("t", 60, t0));
        assert!(!rl.check_n_at("t", 41, t0), "would exceed");
        assert!(rl.check_n_at("t", 40, t0), "the refused batch consumed nothing");
        assert!(!rl.check_n_at("t", 1, t0));
        assert!(!rl.check_n_at("u", u32::MAX, t0), "no overflow");
        assert!(rl.check_n_at("t", 100, t0 + Duration::from_secs(3601)), "window resets");
    }
}
