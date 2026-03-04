use std::time::Duration;

/// Retry strategy for webhook delivery.
///
/// Failed deliveries are retried with exponential backoff between attempts.
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

    /// Create default retry strategy (5 attempts, 100 ms base delay)
    pub fn default_strategy() -> Self {
        Self::new(5, 100)
    }

    /// Get maximum number of attempts
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Calculate delay before the next retry attempt.
    ///
    /// Returns `None` when `attempt >= max_attempts` (no more retries).
    /// The first attempt (`attempt == 0`) is immediate (`Duration::ZERO`).
    /// Subsequent attempts use `2^(attempt-1) * base_delay_ms`, capped at
    /// `max_delay_ms`.
    pub fn next_delay(&self, attempt: u32) -> Option<Duration> {
        if attempt >= self.max_attempts {
            return None;
        }

        if attempt == 0 {
            return Some(Duration::from_millis(0));
        }

        let multiplier = 2_u64.saturating_pow(attempt - 1);
        let delay_ms = self.base_delay_ms.saturating_mul(multiplier);
        let capped_delay = delay_ms.min(self.max_delay_ms);

        Some(Duration::from_millis(capped_delay))
    }

    /// Return `true` if another attempt should be made after `current_attempt`.
    pub fn should_retry(&self, current_attempt: u32) -> bool {
        current_attempt + 1 < self.max_attempts
    }

    /// Return `true` if the given HTTP status code should trigger a retry.
    pub fn should_retry_status(&self, status_code: u16) -> bool {
        match status_code {
            // Success – never retry
            200..=299 => false,
            // Retryable client errors
            408 | 429 => true,
            // Other 4xx – don't retry
            400..=499 => false,
            // Server errors – always retry
            500..=599 => true,
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

        assert_eq!(strategy.next_delay(0), Some(Duration::from_millis(0)));
        assert_eq!(strategy.next_delay(1), Some(Duration::from_millis(100)));
        assert_eq!(strategy.next_delay(2), Some(Duration::from_millis(200)));
        assert_eq!(strategy.next_delay(3), Some(Duration::from_millis(400)));
        assert_eq!(strategy.next_delay(4), Some(Duration::from_millis(800)));
        assert_eq!(strategy.next_delay(5), None);
    }

    #[test]
    fn test_should_retry() {
        let strategy = RetryStrategy::new(3, 100);

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(1));
        assert!(!strategy.should_retry(2));
        assert!(!strategy.should_retry(3));
        assert!(!strategy.should_retry(4));
    }

    #[test]
    fn test_should_retry_status() {
        let strategy = RetryStrategy::default();

        assert!(!strategy.should_retry_status(200));
        assert!(!strategy.should_retry_status(201));
        assert!(!strategy.should_retry_status(204));

        assert!(!strategy.should_retry_status(400));
        assert!(!strategy.should_retry_status(401));
        assert!(!strategy.should_retry_status(403));
        assert!(!strategy.should_retry_status(404));

        assert!(strategy.should_retry_status(408));
        assert!(strategy.should_retry_status(429));

        assert!(strategy.should_retry_status(500));
        assert!(strategy.should_retry_status(502));
        assert!(strategy.should_retry_status(503));
        assert!(strategy.should_retry_status(504));
    }

    #[test]
    fn test_overflow_protection() {
        let strategy = RetryStrategy::new(100, 1000);

        let delay = strategy.next_delay(50);
        assert!(delay.is_some());

        if let Some(d) = delay {
            assert_eq!(d, Duration::from_millis(30_000));
        }
    }
}
