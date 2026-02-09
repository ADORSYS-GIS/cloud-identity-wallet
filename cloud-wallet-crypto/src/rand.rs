use aws_lc_rs::rand;

use crate::error::{Error, ErrorKind, Result};

/// Fills the provided buffer with random bytes.
///
/// # Example
///
/// ```
/// use cloud_wallet_crypto::rand::generate;
/// # use cloud_wallet_crypto::error::Result;
///
/// # fn main() -> Result<()> {
/// let mut buffer = [0u8; 32];
/// generate(&mut buffer)?;
/// #    Ok(())
/// # }
/// ```
pub fn generate(buffer: &mut [u8]) -> Result<()> {
    rand::fill(buffer).map_err(|_| {
        Error::message(
            ErrorKind::RandomGeneration,
            "Failed to generate random bytes",
        )
    })?;
    Ok(())
}
