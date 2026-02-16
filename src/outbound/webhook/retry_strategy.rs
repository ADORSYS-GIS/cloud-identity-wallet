use std::time::Duration;

/// Retry strategy for webhook delivery
/// Failed deliveries are retried with increasing delays between attempts.
#[derive(Debug, Clone)]
pub struct RetryStrategy {
    max_attempts: u32,

    base_delay_ms: u64,

    max_delay_ms: u64,
}

impl RetryStrategy {
    /// Create a new retry strategy
    pub fn new(max_attempts: u32, base_delay_ms: u64) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms: 30_000, // 30 seconds max
        }
    }

    /// Create default retry strategy
    pub fn default_strategy() -> Self {
        Self::new(5, 100)
    }

    /// Create aggressive retry strategy (more attempts, shorter delays)
    pub fn aggressive() -> Self {
        Self::new(10, 50)
    }

    /// Create conservative retry strategy (fewer attempts, longer delays)
    pub fn conservative() -> Self {
        Self::new(3, 500)
    }

    /// Set maximum delay cap
    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Get maximum number of attempts
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Calculate delay before next retry attempt
    pub fn next_delay(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }

        if attempt == 0 {
            // First attempt is immediate
            return Some(Duration::from_millis(0));
        }

        // Exponential backoff: 2^(attempt-1)
        let multiplier = 2_u64.saturating_pow(attempt - 1);
        let delay_ms = self.base_delay_ms.saturating_mul(multiplier);

        // Cap at max delay
        let capped_delay = delay_ms.min(self.max_delay_ms);

        Some(Duration::from_millis(capped_delay))
    }

    /// Check if we should retry after a given attempt
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }

    /// Check if an HTTP status code should trigger a retry
    pub fn should_retry_status(&self, status_code: u16) -> bool {
        match status_code {
            // Success - don't retry
            200..=299 => false,

            // Client errors - don't retry
            408 | 429 => true,
            400..=499 => false,

            // Server errors - retry
            500..=599 => true,

            // Other codes - don't retry
            _ => false,
        }
    }

    /// Get all retry delays for visualization/testing
    pub fn get_all_delays(&self) -> Vec<Duration> {
        (0..self.max_attempts)
            .filter_map(|attempt| self.next_delay(attempt))
            .collect()
    }
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::default_strategy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_strategy() {
        let strategy = RetryStrategy::default_strategy();

        assert_eq!(strategy.max_attempts(), 5);

        // Test delays: 0ms, 100ms, 200ms, 400ms, 800ms
        assert_eq!(strategy.next_delay(0), Some(Duration::from_millis(0)));
        assert_eq!(strategy.next_delay(1), Some(Duration::from_millis(100)));
        assert_eq!(strategy.next_delay(2), Some(Duration::from_millis(200)));
        assert_eq!(strategy.next_delay(3), Some(Duration::from_millis(400)));
        assert_eq!(strategy.next_delay(4), Some(Duration::from_millis(800)));
        assert_eq!(strategy.next_delay(5), None); // Exceeded max attempts
    }

    #[test]
    fn test_exponential_backoff() {
        let strategy = RetryStrategy::new(10, 100);

        let delays = strategy.get_all_delays();

        // Verify exponential growth
        assert_eq!(delays[0], Duration::from_millis(0));
        assert_eq!(delays[1], Duration::from_millis(100));
        assert_eq!(delays[2], Duration::from_millis(200));
        assert_eq!(delays[3], Duration::from_millis(400));
        assert_eq!(delays[4], Duration::from_millis(800));
        assert_eq!(delays[5], Duration::from_millis(1600));
    }

    #[test]
    fn test_max_delay_cap() {
        let strategy = RetryStrategy::new(10, 1000).with_max_delay(5000);

        // Without cap: 1000, 2000, 4000, 8000, 16000...
        // With 5000 cap: 1000, 2000, 4000, 5000, 5000...
        assert_eq!(strategy.next_delay(1), Some(Duration::from_millis(1000)));
        assert_eq!(strategy.next_delay(2), Some(Duration::from_millis(2000)));
        assert_eq!(strategy.next_delay(3), Some(Duration::from_millis(4000)));
        assert_eq!(strategy.next_delay(4), Some(Duration::from_millis(5000))); // Capped
        assert_eq!(strategy.next_delay(5), Some(Duration::from_millis(5000))); // Capped
    }

    #[test]
    fn test_should_retry() {
        let strategy = RetryStrategy::new(3, 100);

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(1));
        assert!(strategy.should_retry(2));
        assert!(!strategy.should_retry(3));
        assert!(!strategy.should_retry(4));
    }

    #[test]
    fn test_should_retry_status() {
        let strategy = RetryStrategy::default();

        // Success - don't retry
        assert!(!strategy.should_retry_status(200));
        assert!(!strategy.should_retry_status(201));
        assert!(!strategy.should_retry_status(204));

        // Client errors - don't retry (except special cases)
        assert!(!strategy.should_retry_status(400));
        assert!(!strategy.should_retry_status(401));
        assert!(!strategy.should_retry_status(403));
        assert!(!strategy.should_retry_status(404));

        // Special client errors - DO retry
        assert!(strategy.should_retry_status(408)); // Timeout
        assert!(strategy.should_retry_status(429)); // Rate limit

        // Server errors - retry
        assert!(strategy.should_retry_status(500));
        assert!(strategy.should_retry_status(502));
        assert!(strategy.should_retry_status(503));
        assert!(strategy.should_retry_status(504));
    }

    #[test]
    fn test_aggressive_strategy() {
        let strategy = RetryStrategy::aggressive();

        assert_eq!(strategy.max_attempts(), 10);
        assert_eq!(strategy.next_delay(1), Some(Duration::from_millis(50)));
        assert_eq!(strategy.next_delay(2), Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_conservative_strategy() {
        let strategy = RetryStrategy::conservative();

        assert_eq!(strategy.max_attempts(), 3);
        assert_eq!(strategy.next_delay(1), Some(Duration::from_millis(500)));
        assert_eq!(strategy.next_delay(2), Some(Duration::from_millis(1000)));
    }

    #[test]
    fn test_overflow_protection() {
        // Test that very large attempt numbers don't panic
        let strategy = RetryStrategy::new(100, 1000);

        // This would overflow without saturating_* operations
        let delay = strategy.next_delay(50);
        assert!(delay.is_some());

        // Should be capped at max_delay_ms
        if let Some(d) = delay {
            assert_eq!(d, Duration::from_millis(30_000));
        }
    }

    #[test]
    fn test_get_all_delays() {
        let strategy = RetryStrategy::new(4, 100);
        let delays = strategy.get_all_delays();

        assert_eq!(delays.len(), 4);
        assert_eq!(delays[0], Duration::from_millis(0));
        assert_eq!(delays[1], Duration::from_millis(100));
        assert_eq!(delays[2], Duration::from_millis(200));
        assert_eq!(delays[3], Duration::from_millis(400));
    }
}
