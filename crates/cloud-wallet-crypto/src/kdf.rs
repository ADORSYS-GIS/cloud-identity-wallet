//! NIST SP 800-56A Rev. 3 §5.8.2.1 Hash-Based One-Step Key Derivation Function (ConcatKDF).
//!
//! This module exposes [`concat_kdf`] as the general-purpose cryptographic
//! primitive. The caller is responsible for constructing the `other_info` byte
//! sequence according to their protocol's specification (AlgorithmID, PartyUInfo,
//! PartyVInfo, SuppPubInfo, SuppPrivInfo, etc.).
//!
//! Protocol-specific convenience wrappers (e.g. JOSE/RFC 7518 OtherInfo encoding)
//! are intentionally excluded from this module — the KDF layer provides only
//! the generic building block. Consumers should implement their own OtherInfo
//! encoding in the layer that owns the protocol knowledge.
//!
//! # Example
//!
//! ```rust
//! use cloud_wallet_crypto::kdf::concat_kdf;
//! use cloud_wallet_crypto::digest::HashAlg;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let shared_secret = [0u8; 32];
//! let other_info = b"custom-info";
//! let mut key = [0u8; 16];
//! concat_kdf(HashAlg::Sha256, &shared_secret, other_info, &mut key)?;
//! # Ok(())
//! # }
//! ```

use crate::digest::{HashAlg, Hasher};
use crate::error::{ErrorKind, Result};
use crate::utils::error_msg;

/// Derives key material from a shared secret using the NIST ConcatKDF counter
/// loop with caller-supplied `other_info`.
///
/// This is the general-purpose entry point that makes no structural assumptions
/// about the `other_info` byte sequence. The caller is responsible for encoding
/// AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo (including `keydatalen`),
/// and any SuppPrivInfo fields per the applicable specification.
///
/// Each round computes `Hash(counter || Z || other_info)` for
/// `counter = 1 … ceil(output.len() / hash_len)`.
///
/// Only SHA-256, SHA-384, and SHA-512 are supported.
///
/// # Errors
///
/// - [`ErrorKind::UnsupportedAlgorithm`] — `hash` is not SHA-256/384/512.
/// - [`ErrorKind::WrongLength`] — `shared_secret` or `output` is empty, or
///   the number of rounds `ceil(output.len() / hash_len)` would exceed
///   `u32::MAX` (counter overflow per NIST SP 800-56A Rev. 3 §5.8.2.1).
pub fn concat_kdf(
    hash: HashAlg,
    shared_secret: &[u8],
    other_info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    match hash {
        HashAlg::Sha256 | HashAlg::Sha384 | HashAlg::Sha512 => {}
        _ => return Err(ErrorKind::UnsupportedAlgorithm.into()),
    }

    if shared_secret.is_empty() {
        return Err(error_msg(
            ErrorKind::WrongLength,
            "ConcatKDF shared secret (Z) must not be empty",
        ));
    }

    if output.is_empty() {
        return Err(ErrorKind::WrongLength.into());
    }

    // NIST SP 800-56A Rev. 3 §5.8.2.1: the counter starts at 1 and must not
    // exceed 2^32 − 1. The number of rounds is ceil(output.len() / hash_len),
    // which must fit in u32 so that the final counter value is representable.
    let hash_len = hash.digest_size();
    let rounds = output.len().div_ceil(hash_len);
    u32::try_from(rounds).map_err(|_| ErrorKind::WrongLength)?;

    for (i, chunk) in output.chunks_mut(hash_len).enumerate() {
        let counter = u32::try_from(i).expect("round count fits in u32 — checked above") + 1;
        let mut h = Hasher::new(hash);
        h.update(counter.to_be_bytes());
        h.update(shared_secret);
        h.update(other_info);
        let digest = h.finalize();
        chunk.copy_from_slice(&digest.as_ref()[..chunk.len()]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Hasher;
    use hex_literal::hex;

    // Shared secret (Z) from RFC 7518 Appendix C — P-256 ECDH output.
    // Used here as known-answer input for the generic ConcatKDF counter loop,
    // not as a JOSE-specific test vector.
    const Z: [u8; 32] = hex!("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");

    #[test]
    fn test_concat_kdf_rfc7518_vector() {
        // RFC 7518 Appendix C known-answer vector, with OtherInfo manually
        // encoded per RFC 7518 §4.6.2 layout to verify the counter loop.
        let other_info = {
            let mut v = Vec::new();
            let keydatalen_bits: u32 = 16u32 * 8;
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A128GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&keydatalen_bits.to_be_bytes());
            v
        };
        let mut out = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &Z, &other_info, &mut out).unwrap();
        assert_eq!(out, hex!("56aa8deaf8236d205c2228cd71a7101a"));
    }

    #[test]
    fn test_concat_kdf_multi_round() {
        // 48 bytes from SHA-256 (32-byte digest) forces 2 rounds through
        // concat_kdf. Verify by computing the expected output manually.
        let other_info = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A384GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&384u32.to_be_bytes());
            v
        };

        let hash_round = |counter: u32, len: usize| -> Vec<u8> {
            let mut h = Hasher::new(HashAlg::Sha256);
            h.update(counter.to_be_bytes());
            h.update(Z);
            h.update(&other_info);
            h.finalize().as_ref()[..len].to_vec()
        };

        let mut expected = [0u8; 48];
        expected[..32].copy_from_slice(&hash_round(1, 32));
        expected[32..].copy_from_slice(&hash_round(2, 16));

        let mut output = [0u8; 48];
        concat_kdf(HashAlg::Sha256, &Z, &other_info, &mut output).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_concat_kdf_custom_other_info() {
        let other_info = b"AlgorithmID\x00PartyUInfo\x00PartyVInfo\x00SuppPrivInfo";

        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        concat_kdf(HashAlg::Sha256, &Z, other_info, &mut out1).unwrap();
        concat_kdf(HashAlg::Sha256, &Z, other_info, &mut out2).unwrap();
        assert_eq!(out1, out2, "concat_kdf must be deterministic");

        let other_info_2 = b"DifferentInfo";
        let mut out3 = [0u8; 32];
        concat_kdf(HashAlg::Sha256, &Z, other_info_2, &mut out3).unwrap();
        assert_ne!(out1, out3);
    }

    #[test]
    fn test_concat_kdf_empty_other_info() {
        let mut out = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &Z, &[], &mut out).unwrap();
        assert_ne!(out, [0u8; 16]);
    }

    #[test]
    fn test_concat_kdf_keydatalen_decoupled() {
        // concat_kdf decouples keydatalen from output.len():
        // the caller encodes keydatalen into other_info and can choose any
        // value, independent of how many bytes are actually requested.
        let other_info_256 = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A128GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&256u32.to_be_bytes());
            v
        };
        let mut out_short = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &Z, &other_info_256, &mut out_short).unwrap();

        let other_info_128 = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A128GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&128u32.to_be_bytes());
            v
        };
        let mut out_normal = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &Z, &other_info_128, &mut out_normal).unwrap();

        // Different keydatalen values must produce different keys,
        // even though output.len() is identical.
        assert_ne!(out_short, out_normal);
    }

    #[test]
    fn test_concat_kdf_unsupported_hash_rejected() {
        let mut out = [0u8; 16];
        let err = concat_kdf(HashAlg::Sha224, &Z, b"info", &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn test_concat_kdf_empty_shared_secret_rejected() {
        let mut out = [0u8; 16];
        let err = concat_kdf(HashAlg::Sha256, &[], b"info", &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }

    #[test]
    fn test_concat_kdf_empty_output_rejected() {
        let err = concat_kdf(HashAlg::Sha256, &Z, b"info", &mut []).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }

    #[test]
    fn test_concat_kdf_sha384() {
        // Cross-verified against Python cryptography library's ConcatKDFHash
        // with SHA-384, 24-byte output.
        let other_info = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A192GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&192u32.to_be_bytes());
            v
        };
        let mut out = [0u8; 24];
        concat_kdf(HashAlg::Sha384, &Z, &other_info, &mut out).unwrap();
        assert_eq!(
            out,
            hex!("2175d5217f6ca233e7c4114fb17ebdaeea7fbd39289f915b")
        );
    }

    #[test]
    fn test_concat_kdf_sha512() {
        // Cross-verified against Python cryptography library's ConcatKDFHash
        // with SHA-512, 32-byte output.
        let other_info = {
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_be_bytes());
            v.extend_from_slice(b"A256GCM");
            v.extend_from_slice(&5u32.to_be_bytes());
            v.extend_from_slice(b"Alice");
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(b"Bob");
            v.extend_from_slice(&256u32.to_be_bytes());
            v
        };
        let mut out = [0u8; 32];
        concat_kdf(HashAlg::Sha512, &Z, &other_info, &mut out).unwrap();
        assert_eq!(
            out,
            hex!("93e47a4a9ce12aefb8f90691a93317ec6573981269604d6b1631e2c8aa0d4bfa")
        );
    }
}
