//! mDoc (ISO 18013-5) parsing support.
//!
//! This module provides foundational CBOR parsing for `mso_mdoc` credentials
//! returned by OpenID4VCI issuers. The entry point is [`ParsedMdoc::parse`],
//! which decodes a base64url-encoded `IssuerSigned` structure into a typed
//! [`ParsedMdoc`].
//!
//! # References
//!
//! - ISO/IEC 18013-5 — `IssuerSigned`, `MSO`, `ValidityInfo` CBOR structures
//! - [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — CBOR
//! - [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — COSE_Sign1

pub mod error;
mod parser;
#[cfg(test)]
mod tests;
pub mod verifier;

pub use error::{MdocError, Result};
pub use parser::{IssuerSignedItem, ParsedMdoc};
pub use verifier::verify_digests;

use cloud_wallet_crypto::digest::HashAlg;

/// The hash algorithm used in the MSO `digestAlgorithm` field.
///
/// ISO 18013-5 §9.1.2.5 defines the permitted set as SHA-256, SHA-384, and SHA-512.
/// A `DigestAlgorithm` value guarantees the algorithm has already been validated
/// as one of the three supported variants — the parser rejects anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 (32-byte output).
    Sha256,
    /// SHA-384 (48-byte output).
    Sha384,
    /// SHA-512 (64-byte output).
    Sha512,
}

impl TryFrom<&str> for DigestAlgorithm {
    type Error = MdocError;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match s {
            "SHA-256" => Ok(Self::Sha256),
            "SHA-384" => Ok(Self::Sha384),
            "SHA-512" => Ok(Self::Sha512),
            other => Err(MdocError::UnsupportedDigestAlgorithm {
                algorithm: other.to_owned(),
            }),
        }
    }
}

impl DigestAlgorithm {
    /// Expected hash output size in bytes.
    pub fn digest_size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The IANA/MSO string identifier (e.g. `"SHA-256"`).
    pub fn as_mso_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

impl std::fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_mso_str())
    }
}

// Bridge to the crypto layer. Placed here so that all `DigestAlgorithm`
impl From<DigestAlgorithm> for HashAlg {
    fn from(alg: DigestAlgorithm) -> Self {
        match alg {
            DigestAlgorithm::Sha256 => HashAlg::Sha256,
            DigestAlgorithm::Sha384 => HashAlg::Sha384,
            DigestAlgorithm::Sha512 => HashAlg::Sha512,
        }
    }
}
