//! Cryptographically secure random number generation.
//!
//! # Examples
//!
//! ## Generate Random Bytes
//!
//! ```rust
//! use cloud_wallet_crypto::rand;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut buffer = [0u8; 32];
//! rand::fill_bytes(&mut buffer)?;
//! // buffer now contains 32 random bytes
//! # Ok(())
//! # }
//! ```
//!
//! In practice, failures are so rare that panicking on error is often acceptable
//! for cryptographic operations that cannot proceed without randomness.

use aws_lc_rs::rand;

use crate::error::{Error, ErrorKind, Result};

/// Fills the provided buffer with cryptographically secure random bytes
/// using the operating system's secure random number generator.
///
/// This is an alias for [`fill_bytes`] to maintain compatibility with `rand::fill` style calls.
pub fn fill(buffer: &mut [u8]) -> Result<()> {
    fill_bytes(buffer)
}

/// Fills the provided buffer with cryptographically secure random bytes
/// using the operating system's secure random number generator.
///
/// # Examples
///
/// ```rust
/// use cloud_wallet_crypto::rand;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut key = [0u8; 32];
/// rand::fill_bytes(&mut key)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// `ErrorKind::RandomGeneration` if the random number generator
/// fails. This is extremely rare.
pub fn fill_bytes(buffer: &mut [u8]) -> Result<()> {
    rand::fill(buffer).map_err(|_| {
        Error::message(
            ErrorKind::RandomGeneration,
            "Failed to generate random bytes",
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_bytes() {
        let mut buffer = [0u8; 32];
        let original_buffer = buffer;
        fill_bytes(&mut buffer).unwrap();

        // Check that the buffer has been modified
        assert_ne!(buffer, original_buffer);

        // It's statistically improbable for a CSPRNG to produce all zeros
        assert!(buffer.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn test_fill_bytes_different_runs() {
        let mut buffer1 = [0u8; 32];
        let mut buffer2 = [0u8; 32];

        fill_bytes(&mut buffer1).unwrap();
        fill_bytes(&mut buffer2).unwrap();

        // It's extremely unlikely that two separate calls will produce the same output
        assert_ne!(buffer1, buffer2);
    }
}
