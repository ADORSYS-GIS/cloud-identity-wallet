//! # KMS Provider Interface and Implementations
//!
//! ## Provided Implementations
//!
//! - [`LocalProvider`]: An implementation that uses a locally generated, in-memory master key.
//!   It is intended for development and testing.
//! - [`AwsProvider`]: An implementation that uses AWS KMS for master key management
//! and encryption/decryption of data encryption keys.

#[cfg(feature = "aws-kms")]
mod aws;
#[cfg(feature = "local-kms")]
mod local;

#[cfg(feature = "aws-kms")]
pub use aws::AwsProvider;
#[cfg(feature = "local-kms")]
pub use local::LocalProvider;

/// KMS provider trait for encrypting and decrypting data.
#[async_trait::async_trait]
pub trait Provider: Send + Sync + 'static {
    /// Encrypts data in place.
    ///
    /// `aad` additional authenticated data can be used to provide
    /// additional encryption context to the encryption process.
    /// It is not encrypted, but it is authenticated and can be empty.
    ///
    /// The input data is encrypted, and the result, including
    /// any necessary metadata is stored back in the input buffer.
    async fn encrypt<T>(&self, aad: &[u8], plain_inout: &mut T) -> crate::Result<()>
    where
        T: AsMut<[u8]> + for<'a> Extend<&'a u8> + Send;

    /// Decrypts data in place.
    ///
    /// `aad` additional authenticated data should match the one used during encryption,
    /// otherwise decryption will fail.
    ///
    /// The input buffer contains the ciphertext and any associated metadata.
    /// The decryption is performed in-place, and a slice of the original buffer
    /// containing the plaintext is returned.
    async fn decrypt<'a>(&self, aad: &[u8], cipher_inout: &'a mut [u8]) -> crate::Result<&'a [u8]>;
}
