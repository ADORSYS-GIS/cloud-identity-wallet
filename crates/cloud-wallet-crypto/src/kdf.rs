//! NIST SP 800-56A Rev. 3 §5.8.2.1 Hash-Based One-Step Key Derivation Function (ConcatKDF).
//!
//! Used in JOSE for ECDH-ES key derivation per [RFC 7518 §4.6.2].
//!
//! # Example
//!
//! ```rust
//! use cloud_wallet_crypto::kdf::{concat_kdf, ConcatKdfParams};
//! use cloud_wallet_crypto::digest::HashAlg;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let shared_secret = [0u8; 32]; // from ECDH agreement
//! let params = ConcatKdfParams {
//!     algorithm_id: b"A128GCM",
//!     party_u_info: b"Alice",
//!     party_v_info: b"Bob",
//! };
//! let mut key = [0u8; 16];
//! concat_kdf(HashAlg::Sha256, &shared_secret, &params, &mut key)?;
//! # Ok(())
//! # }
//! ```
//!
//! [RFC 7518 §4.6.2]: https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2

use crate::digest::{HashAlg, Hasher};
use crate::error::{ErrorKind, Result};
use crate::utils::error_msg;

/// OtherInfo fields for ConcatKDF per RFC 7518 §4.6.2.
///
/// Each field is encoded as a big-endian `u32` length prefix followed by the
/// raw bytes. Pass decoded (not base64url) bytes for `party_u_info` and
/// `party_v_info`.
#[derive(Debug)]
pub struct ConcatKdfParams<'a> {
    /// ASCII algorithm identifier (e.g. `b"A128GCM"`).
    pub algorithm_id: &'a [u8],
    /// Decoded `apu` value — may be empty.
    pub party_u_info: &'a [u8],
    /// Decoded `apv` value — may be empty.
    pub party_v_info: &'a [u8],
}

/// Derives key material from a shared secret using NIST ConcatKDF.
///
/// `output.len()` determines the byte count produced; `keydatalen` encoded
/// into OtherInfo is `output.len() * 8` bits.
///
/// Pass `SharedSecret::as_bytes()` directly — do not copy into a plain `Vec`.
/// Store the derived key in [`zeroize::Zeroizing`] or [`crate::secret::Secret`].
///
/// Only SHA-256, SHA-384, and SHA-512 are supported (RFC 7518 §4.6).
///
/// # Errors
///
/// - [`ErrorKind::UnsupportedAlgorithm`] — `hash` is not SHA-256/384/512, or
///   `algorithm_id` is empty (RFC 7518 §4.6.2 requires a non-empty identifier).
/// - [`ErrorKind::WrongLength`] — `shared_secret` or `output` is empty, or
///   byte-length of output overflows `u32`.
pub fn concat_kdf(
    hash: HashAlg,
    shared_secret: &[u8],
    params: &ConcatKdfParams<'_>,
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

    if params.algorithm_id.is_empty() {
        return Err(error_msg(
            ErrorKind::UnsupportedAlgorithm,
            "ConcatKDF algorithm_id must not be empty (RFC 7518 §4.6.2)",
        ));
    }

    if output.is_empty() {
        return Err(ErrorKind::WrongLength.into());
    }

    // keydatalen in bits — must fit in u32 per spec
    let keydatalen_bits = u32::try_from(output.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(ErrorKind::WrongLength)?;

    // Precompute u32 field lengths — catches pathological inputs before the loop
    // and removes three silent truncating `as u32` casts.
    let alg_id_len = u32::try_from(params.algorithm_id.len())
        .map_err(|_| error_msg(ErrorKind::WrongLength, "algorithm_id length overflows u32"))?;
    let party_u_len = u32::try_from(params.party_u_info.len())
        .map_err(|_| error_msg(ErrorKind::WrongLength, "party_u_info length overflows u32"))?;
    let party_v_len = u32::try_from(params.party_v_info.len())
        .map_err(|_| error_msg(ErrorKind::WrongLength, "party_v_info length overflows u32"))?;

    let hash_len = hash.digest_size();
    let rounds = output.len().div_ceil(hash_len);
    let mut written = 0usize;

    // keydatalen_bits check above proves output.len() <= u32::MAX / 8, and
    // hash_len >= 32, so rounds <= u32::MAX / 8 / 32 ~= 16.7M — well within u32.
    let rounds_u32 = u32::try_from(rounds)
        .expect("ConcatKDF round count invariant violated — keydatalen_bits check above guarantees rounds <= u32::MAX");

    for counter in 1u32..=rounds_u32 {
        // NIST SP 800-56A §5.8.2.1: Hash(counter || Z || OtherInfo)
        // Sequential updates avoid an intermediate concatenation buffer.
        let mut h = Hasher::new(hash);
        h.update(counter.to_be_bytes());
        h.update(shared_secret);
        // OtherInfo: RFC 7518 §4.6.2 — each field is u32-length-prefixed
        h.update(alg_id_len.to_be_bytes());
        h.update(params.algorithm_id);
        h.update(party_u_len.to_be_bytes());
        h.update(params.party_u_info);
        h.update(party_v_len.to_be_bytes());
        h.update(params.party_v_info);
        h.update(keydatalen_bits.to_be_bytes());

        let digest = h.finalize();
        let to_copy = (output.len() - written).min(hash_len);
        output[written..written + to_copy].copy_from_slice(&digest.as_ref()[..to_copy]);
        written += to_copy;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Hasher;
    use hex_literal::hex;

    // Shared secret (Z) from RFC 7518 Appendix C — P-256 ECDH output.
    // Computed via ECDH(d_s="VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
    //                   Q_e={"x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
    //                        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"})
    // https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
    const RFC7518_Z: [u8; 32] =
        hex!("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");

    #[test]
    fn test_rfc7518_appendix_c_single_round() {
        // enc=A128GCM, apu=base64url("Alice"), apv=base64url("Bob")
        // Party info bytes are the decoded values passed into ConcatKDF.
        // Expected CEK: "VqqN6vgjbSBcIijNcacQGg" (RFC 7518 Appendix C)
        let params = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        };
        let mut output = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params, &mut output).unwrap();
        assert_eq!(output, hex!("56aa8deaf8236d205c2228cd71a7101a"));
    }

    #[test]
    fn test_multi_round_output_exceeds_hash_size() {
        // 48 bytes from SHA-256 (32-byte digest) forces 2 rounds.
        // keydatalen = 48 * 8 = 384 bits (encoded in OtherInfo).
        // Expected value computed by calling SHA-256 directly for each counter value,
        // verifying that the loop correctly increments the counter and truncates round 2.
        let params = ConcatKdfParams {
            algorithm_id: b"A384GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        };

        // Compute expected output by driving the hash directly.
        let hash_round = |counter: u32, len: usize| -> Vec<u8> {
            let mut h = Hasher::new(HashAlg::Sha256);
            h.update(counter.to_be_bytes());
            h.update(RFC7518_Z);
            h.update(7u32.to_be_bytes()); // len("A384GCM")
            h.update(b"A384GCM");
            h.update(5u32.to_be_bytes()); // len("Alice")
            h.update(b"Alice");
            h.update(3u32.to_be_bytes()); // len("Bob")
            h.update(b"Bob");
            h.update(384u32.to_be_bytes()); // keydatalen bits
            h.finalize().as_ref()[..len].to_vec()
        };
        let mut expected = [0u8; 48];
        expected[..32].copy_from_slice(&hash_round(1, 32));
        expected[32..].copy_from_slice(&hash_round(2, 16));

        let mut output = [0u8; 48];
        concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params, &mut output).unwrap();
        assert_eq!(output, expected);

        // keydatalen is part of OtherInfo — different output lengths must diverge.
        let mut out_32 = [0u8; 32];
        concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params, &mut out_32).unwrap();
        assert_ne!(&out_32[..], &output[..32]);
    }

    #[test]
    fn test_empty_party_info() {
        let params_empty = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"",
            party_v_info: b"",
        };
        let params_non_empty = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        };
        let mut out_empty = [0u8; 16];
        let mut out_non_empty = [0u8; 16];
        concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params_empty, &mut out_empty).unwrap();
        concat_kdf(
            HashAlg::Sha256,
            &RFC7518_Z,
            &params_non_empty,
            &mut out_non_empty,
        )
        .unwrap();
        // Different party info must produce different keys
        assert_ne!(out_empty, out_non_empty);
    }

    #[test]
    fn test_unsupported_hash_rejected() {
        let params = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"",
            party_v_info: b"",
        };
        let mut out = [0u8; 16];
        let err = concat_kdf(HashAlg::Sha224, &RFC7518_Z, &params, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);

        let err = concat_kdf(HashAlg::Sha3_256, &RFC7518_Z, &params, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn test_empty_algorithm_id_rejected() {
        // RFC 7518 §4.6.2 mandates a non-empty algorithm identifier.
        let params = ConcatKdfParams {
            algorithm_id: b"",
            party_u_info: b"",
            party_v_info: b"",
        };
        let mut out = [0u8; 16];
        let err = concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn test_empty_output_rejected() {
        let params = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"",
            party_v_info: b"",
        };
        let err = concat_kdf(HashAlg::Sha256, &RFC7518_Z, &params, &mut []).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }

    #[test]
    fn test_different_algorithm_ids_produce_different_keys() {
        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        concat_kdf(
            HashAlg::Sha256,
            &RFC7518_Z,
            &ConcatKdfParams {
                algorithm_id: b"A128GCM",
                party_u_info: b"",
                party_v_info: b"",
            },
            &mut out1,
        )
        .unwrap();
        concat_kdf(
            HashAlg::Sha256,
            &RFC7518_Z,
            &ConcatKdfParams {
                algorithm_id: b"A256GCM",
                party_u_info: b"",
                party_v_info: b"",
            },
            &mut out2,
        )
        .unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_sha384_known_answer() {
        // Z = RFC 7518 Appendix C shared secret.
        // alg=A192GCM, apu=Alice, apv=Bob, output=24 bytes (192 bits).
        // Expected value produced by the `cryptography` library's ConcatKDFHash
        // (NIST SP 800-56A), an independent full KDF implementation including the
        // counter loop and truncation. Cross-checked against a standalone Python
        // hashlib computation; both agree. Verified with cryptography 49.0.0.
        // interoperability evidence; RFC 7518 provides no official SHA-384 vector.
        let params = ConcatKdfParams {
            algorithm_id: b"A192GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        };
        let mut out = [0u8; 24];
        concat_kdf(HashAlg::Sha384, &RFC7518_Z, &params, &mut out).unwrap();
        assert_eq!(
            out,
            hex!("2175d5217f6ca233e7c4114fb17ebdaeea7fbd39289f915b")
        );
    }

    #[test]
    fn test_sha512_known_answer() {
        // Z = RFC 7518 Appendix C shared secret.
        // alg=A192GCM, apu=Alice, apv=Bob, output=24 bytes (192 bits).
        // Expected value produced by the `cryptography` library's ConcatKDFHash
        // (NIST SP 800-56A), an independent full KDF implementation including the
        // counter loop and truncation. Cross-checked against a standalone Python
        // hashlib computation; both agree. Verified with cryptography 49.0.0.
        // interoperability evidence; RFC 7518 provides no official SHA-512 vector.
        let params = ConcatKdfParams {
            algorithm_id: b"A256GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        };
        let mut out = [0u8; 32];
        concat_kdf(HashAlg::Sha512, &RFC7518_Z, &params, &mut out).unwrap();
        assert_eq!(
            out,
            hex!("93e47a4a9ce12aefb8f90691a93317ec6573981269604d6b1631e2c8aa0d4bfa")
        );
    }

    #[test]
    fn test_empty_shared_secret_rejected() {
        let params = ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"",
            party_v_info: b"",
        };
        let mut out = [0u8; 16];
        let err = concat_kdf(HashAlg::Sha256, &[], &params, &mut out).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }
}
