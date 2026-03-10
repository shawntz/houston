use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    max_attempts: u32,
    window_seconds: u64,
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            max_attempts,
            window_seconds,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request is allowed, false if rate limited.
    pub fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_seconds);

        let attempts = buckets.entry(key.to_string()).or_default();

        // Remove expired entries
        attempts.retain(|t| now.duration_since(*t) < window);

        if attempts.len() >= self.max_attempts as usize {
            false
        } else {
            attempts.push(now);
            true
        }
    }

    /// Clean up old entries to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_seconds);
        buckets.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < window);
            !attempts.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(limiter.check("user1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(limiter.check("user1"));
        assert!(!limiter.check("user1"));
    }

    #[test]
    fn test_rate_limiter_independent_keys() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("user1"));
        assert!(limiter.check("user2"));
        assert!(!limiter.check("user1"));
    }
}
