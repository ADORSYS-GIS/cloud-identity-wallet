//! JSON Web Encryption (JWE) — compact serialization, RFC 7516.
//!
//! # Supported Algorithms
//!
//! Key management (`alg`):
//! - `RSA-OAEP-256` (RFC 7518 §4.3), `RSA-OAEP-384`, `RSA-OAEP-512` (RFC 8230)
//! - `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` (RFC 7518 §4.6)
//!
//! Content encryption (`enc`):
//! - `A128GCM`, `A256GCM` (RFC 7518 §5.3)
//!
//! # FIPS Compatibility
//!
//! When the `fips` feature is enabled, curve availability follows the aws-lc-rs FIPS
//! policy. P-521 key agreement may be restricted in some FIPS-validated configurations;
//! prefer P-256 or P-384 for maximum portability when combining `fips` and `jwe`.
//!
//! # Example
//!
//! ```rust
//! use cloud_wallet_crypto::ecdh::{EcdhCurve, EphemeralEcdhKey, EcdhPublicKey, StaticEcdhKey};
//! use cloud_wallet_crypto::jwe::{
//!     AlgAlgorithm, EncAlgorithm, JweHeader,
//!     encrypt, JweEncryptKey, decrypt, JweDecryptKey,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Recipient generates a static ECDH key pair.
//! let static_key = StaticEcdhKey::generate(EcdhCurve::P256)?;
//! let mut pub_buf = vec![0u8; EcdhCurve::P256.public_key_len()];
//! let pub_bytes = static_key.public_key_bytes(&mut pub_buf)?;
//! let recipient_pub = EcdhPublicKey::from_bytes(EcdhCurve::P256, pub_bytes)?;
//!
//! // Encrypt a message.
//! let header = JweHeader {
//!     alg: AlgAlgorithm::EcdhEs,
//!     enc: EncAlgorithm::A256Gcm,
//!     epk: None,
//!     apu: None,
//!     apv: None,
//!     kid: None,
//!     typ: None,
//!     cty: None,
//!     crit: None,
//! };
//! let token = encrypt(header, b"hello world", JweEncryptKey::Ecdh(&recipient_pub))?;
//!
//! // Decrypt the message.
//! let plaintext = decrypt(&token, JweDecryptKey::Ecdh(&static_key))?;
//! assert_eq!(plaintext, b"hello world");
//! # Ok(())
//! # }
//! ```

pub(crate) mod compact;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod header;

#[cfg(test)]
mod tests;

pub use decrypt::{JweDecryptKey, decrypt};
pub use encrypt::{JweEncryptKey, encrypt};
pub use header::{AlgAlgorithm, EncAlgorithm, JweHeader};
