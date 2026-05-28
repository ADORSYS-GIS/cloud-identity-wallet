//! Digest integrity verification for ISO 18013-5 mDoc credentials.
//!
//! This module implements the `valueDigests` check described in ISO/IEC 18013-5 §9.1.2:
//! every `IssuerSignedItem` must hash (under the algorithm named in the MSO
//! `digestAlgorithm` field) to the corresponding entry in `valueDigests`.
//!
//! # Crypto backend
//!
//! Hashing is performed via [`cloud_wallet_crypto::digest::HashAlg`], which delegates to
//! `aws_lc_rs::digest`. No separate `sha2` crate is used.
//!
//! # Constant-time comparison
//!
//! The computed digest is compared against the stored value with
//! [`subtle::ConstantTimeEq`] to prevent timing-oracle attacks (OWASP A02).

use subtle::ConstantTimeEq as _;

use cloud_wallet_crypto::digest::HashAlg;

use super::error::{MdocError, Result};
use super::parser::ParsedMdoc;

/// Verifies that every `IssuerSignedItem` in `parsed` hashes to its corresponding
/// entry in the MSO `valueDigests` map (ISO/IEC 18013-5 §9.1.2).
///
/// # Algorithm selection
///
/// The algorithm is determined by the MSO `digestAlgorithm` field stored in
/// [`ParsedMdoc::digest_algorithm`]. Supported values:
///
/// | MSO string  | Algorithm         |
/// |-------------|-------------------|
/// | `"SHA-256"` | SHA-256 (32 bytes) |
/// | `"SHA-384"` | SHA-384 (48 bytes) |
/// | `"SHA-512"` | SHA-512 (64 bytes) |
///
/// Any other string returns [`MdocError::UnsupportedDigestAlgorithm`].
///
/// # Errors
///
/// - [`MdocError::UnsupportedDigestAlgorithm`] — unrecognised `digestAlgorithm` string.
/// - [`MdocError::MissingDigest`] — no `valueDigests` entry for a presented item's
///   namespace + `digestID`.
/// - [`MdocError::DigestMismatch`] — the computed hash does not match the stored digest.
pub fn verify_digests(parsed: &ParsedMdoc) -> Result<()> {
    let alg = parse_digest_algorithm(&parsed.digest_algorithm)?;

    for (namespace, items) in &parsed.name_spaces {
        for item in items {
            let computed = alg.hash(&item.raw_tag24_bytes);

            let stored = parsed
                .value_digests
                .get(namespace)
                .and_then(|ns_map| ns_map.get(&item.digest_id))
                .ok_or_else(|| MdocError::MissingDigest {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                })?;

            // Constant-time comparison — prevents timing-oracle attacks on digest values.
            let matches: bool = computed.as_ref().ct_eq(stored.as_slice()).into();
            if !matches {
                return Err(MdocError::DigestMismatch {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                });
            }
        }
    }

    Ok(())
}

/// Maps the MSO `digestAlgorithm` string to a [`HashAlg`] variant.
///
/// Only SHA-256, SHA-384, and SHA-512 are permitted by IANA COSE Algorithms for
/// use in mDoc (ISO/IEC 18013-5 §9.1.2 Table 1).
fn parse_digest_algorithm(algorithm: &str) -> Result<HashAlg> {
    match algorithm {
        "SHA-256" => Ok(HashAlg::Sha256),
        "SHA-384" => Ok(HashAlg::Sha384),
        "SHA-512" => Ok(HashAlg::Sha512),
        other => Err(MdocError::UnsupportedDigestAlgorithm {
            algorithm: other.to_owned(),
        }),
    }
}
