//! # Thread Safe Nonce Generation
//!
//! [`NonceGenerator`] uses an internal counter to generate unique nonces. Generated nonces
//! are 12 bytes long and are guaranteed to be unique within the same generator instance.
//! The counter is incremented on each call to [`next()`](NonceGenerator::next()).
//! Nonces are constructed by concatenating the prefix (4 bytes) with the counter (8 bytes).

use cloud_wallet_crypto::aead::NONCE_LENGTH;
use std::sync::atomic::{AtomicU64, Ordering};

/// A thread-safe, atomic nonce generator.
///
/// This generator combines a fixed prefix with an incrementing counter to produce unique nonces.
/// It is designed to prevent nonce reuse across different threads or application instances,
/// as long as the prefix is unique.
///
/// The generator can be configured with a usage limit to prevent excessive nonce generation
/// under the same configuration, which is a safeguard against potential security risks like
/// counter overflow or nonce collision.
pub struct NonceGenerator {
    limit: u64,
    generated: AtomicU64,
    prefix: [u8; 4],
    counter: AtomicU64,
}

impl NonceGenerator {
    /// Creates a new `NonceGenerator` with default settings.
    ///
    /// By default, the generator has a limit of `u64::MAX`,
    /// a zero prefix, and starts the counter at zero.
    pub fn new() -> Self {
        Self {
            limit: u64::MAX,
            generated: AtomicU64::new(0),
            prefix: [0u8; 4],
            counter: AtomicU64::new(0),
        }
    }

    /// Sets a 4-byte prefix for all generated nonces.
    pub fn with_prefix(self, prefix: [u8; 4]) -> Self {
        Self { prefix, ..self }
    }

    /// Sets the initial value of the counter.
    ///
    /// This allows the generator to resume from a specific point.
    pub fn with_counter(self, counter: u64) -> Self {
        Self {
            counter: AtomicU64::new(counter),
            ..self
        }
    }

    /// Sets a limit on the number of nonces that can be generated.
    ///
    /// If [`next()`] is called after the limit has been reached, it will return an error.
    ///
    /// [`next()`]: Self::next
    pub fn with_limit(self, limit: u64) -> Self {
        Self { limit, ..self }
    }

    /// Returns the internal prefix.
    pub fn prefix(&self) -> [u8; 4] {
        self.prefix
    }

    /// Returns the current counter value.
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Returns the number of nonces generated so far.
    pub fn generated(&self) -> u64 {
        self.generated.load(Ordering::Relaxed)
    }

    /// Returns the generation limit.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Advances the counter and returns the next nonce.
    ///
    /// # Errors
    ///
    /// Returns a `NonceError` if the generation limit has been exceeded.
    #[inline]
    pub fn next(&self) -> Result<[u8; NONCE_LENGTH], NonceError> {
        let generated = self.generated.fetch_add(1, Ordering::Relaxed);
        if generated >= self.limit {
            return Err(NonceError::new("Nonce limit exceeded"));
        }
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..].copy_from_slice(&count.to_be_bytes());
        Ok(nonce)
    }
}

impl Clone for NonceGenerator {
    fn clone(&self) -> Self {
        Self {
            limit: self.limit,
            generated: AtomicU64::new(self.generated.load(Ordering::Relaxed)),
            prefix: self.prefix,
            counter: AtomicU64::new(self.counter.load(Ordering::Relaxed)),
        }
    }
}

impl std::fmt::Debug for NonceGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceGenerator")
            .field("limit", &self.limit)
            .field("generated", &self.generated)
            .field("prefix", &self.prefix)
            .field("counter", &self.counter)
            .finish()
    }
}

impl Default for NonceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// An error type for the nonce generator.
#[derive(Debug)]
pub struct NonceError(String);

impl NonceError {
    /// Creates a new `NonceError` with a custom message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NonceError {}

impl From<NonceError> for crate::Error {
    fn from(error: NonceError) -> Self {
        crate::Error::Crypto(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_crypto::aead::NONCE_LENGTH;

    #[test]
    fn test_nonce_generator_next() {
        let generator = NonceGenerator::new();
        let nonce1 = generator.next().unwrap();
        let nonce2 = generator.next().unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_generator_with_prefix() {
        let prefix = [1, 2, 3, 4];
        let generator = NonceGenerator::new().with_prefix(prefix);
        let nonce = generator.next().unwrap();
        assert_eq!(&nonce[..4], &prefix);
    }

    #[test]
    fn test_nonce_generator_with_counter() {
        let generator = NonceGenerator::new().with_counter(100);
        let nonce = generator.next().unwrap();
        let mut expected_nonce = [0u8; NONCE_LENGTH];
        expected_nonce[4..].copy_from_slice(&100u64.to_be_bytes());
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn test_nonce_generator_limit() {
        let generator = NonceGenerator::new().with_limit(2);
        assert!(generator.next().is_ok());
        assert!(generator.next().is_ok());
        let result = generator.next();
        assert!(result.is_err());
        match result.err().unwrap() {
            NonceError(msg) => assert_eq!(msg, "Nonce limit exceeded"),
        }
    }

    #[test]
    fn test_nonce_uniqueness_across_threads() {
        let generator = std::sync::Arc::new(NonceGenerator::new());
        let mut handles = vec![];
        let num_threads = 10;
        let nonces_per_thread = 100;

        for _ in 0..num_threads {
            let generator_clone = generator.clone();
            let handle = std::thread::spawn(move || {
                let mut nonces = Vec::new();
                for _ in 0..nonces_per_thread {
                    nonces.push(generator_clone.next().unwrap());
                }
                nonces
            });
            handles.push(handle);
        }

        let mut all_nonces = std::collections::HashSet::new();
        let mut total_nonces = 0;
        for handle in handles {
            let nonces = handle.join().unwrap();
            for nonce in nonces {
                all_nonces.insert(nonce);
            }
            total_nonces += nonces_per_thread;
        }

        assert_eq!(all_nonces.len(), total_nonces);
    }
}
