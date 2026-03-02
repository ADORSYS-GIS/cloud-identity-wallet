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
    pub fn should_retry(&self, current_attempt: u32) -> bool {
        current_attempt + 1 < self.max_attempts
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
    fn test_should_retry() {
        let strategy = RetryStrategy::new(3, 100);

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(1));
        assert!(!strategy.should_retry(2)); // 2 + 1 = 3, 3 < 3 is false
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
}
