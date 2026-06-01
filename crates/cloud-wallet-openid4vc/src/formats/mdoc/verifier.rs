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
/// The algorithm is determined by [`ParsedMdoc::digest_algorithm`], which the parser
/// has already validated. The conversion to [`HashAlg`] is infallible.
///
/// # Selective disclosure
///
/// Only items present in `name_spaces` (the disclosed set) are checked.
/// Entries in `value_digests` with no corresponding disclosed item are intentionally
/// skipped — selective disclosure is explicitly permitted by ISO/IEC 18013-5 §9.1.2.
///
/// # Errors
///
/// - [`MdocError::MissingDigest`] — no `valueDigests` entry for a presented item's
///   namespace + `digestID`.
/// - [`MdocError::DigestMismatch`] — the computed hash does not match the stored digest.
#[must_use = "digest verification failure must be handled"]
pub fn verify_digests(parsed: &ParsedMdoc) -> Result<()> {
    let alg = HashAlg::from(parsed.digest_algorithm);

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

            // `parse_value_digests` enforces that every stored digest has exactly
            // `digest_algorithm.digest_size()` bytes; `aws_lc_rs::digest` always
            // produces the same fixed output length. Both slices are therefore
            // guaranteed equal-length, so `ct_eq` runs in unconditional constant
            // time over all N content bytes — `subtle` only provides constant-time
            // behaviour when both slices have the same length.
            let digest_ok: bool = computed.as_ref().ct_eq(stored.as_slice()).into();
            if !digest_ok {
                return Err(MdocError::DigestMismatch {
                    namespace: namespace.clone(),
                    digest_id: item.digest_id,
                });
            }
        }
    }

    Ok(())
}
