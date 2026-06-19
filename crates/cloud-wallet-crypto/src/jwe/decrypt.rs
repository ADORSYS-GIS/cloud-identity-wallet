//! JWE content decryption (RFC 7516).

use zeroize::Zeroizing;

use crate::aead::{self, NONCE_LENGTH, TAG_LENGTH};
use crate::aes_kek::KeyEncryptionKey;
use crate::digest::HashAlg;
use crate::ecdh::StaticEcdhKey;
use crate::error::{ErrorKind, Result};
use crate::kdf::{ConcatKdfParams, concat_kdf};
use crate::rsa::oaep::DecryptingKey as RsaDecryptingKey;
use crate::utils::error_msg;

use super::compact::{b64url_decode, epk_jwk_to_ecdh_pub, parse_compact};
use super::header::{AlgAlgorithm, JweHeader};

/// Key supplied by the caller for JWE decryption.
///
/// The variant must match the `alg` field in the token's protected header;
/// a mismatch returns [`ErrorKind::UnsupportedAlgorithm`].
#[non_exhaustive]
pub enum JweDecryptKey<'a> {
    /// RSA private key for RSA-OAEP-256, RSA-OAEP-384, or RSA-OAEP-512.
    Rsa(&'a RsaDecryptingKey),
    /// ECDH recipient static private key for ECDH-ES, ECDH-ES+A128KW, or ECDH-ES+A256KW.
    Ecdh(&'a StaticEcdhKey),
}

impl std::fmt::Debug for JweDecryptKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.debug_tuple("JweDecryptKey::Rsa").finish(),
            Self::Ecdh(k) => f
                .debug_tuple("JweDecryptKey::Ecdh")
                .field(&k.curve())
                .finish(),
        }
    }
}

/// Decrypt a compact JWE token and return the plaintext.
///
/// The strict validation gate (parse → deserialize → validate → alg/key check →
/// ECDH curve check → crypto) means no cryptographic work occurs until all
/// attacker-controlled fields have been validated.
///
/// The raw ASCII bytes of the first compact segment are used as AAD for
/// AES-GCM, exactly as produced by [`fn@crate::jwe::encrypt`].
///
/// The returned plaintext is wrapped in [`Zeroizing`] so that its heap memory
/// is wiped when the value drops. Callers with sensitive plaintext should avoid
/// copying it into plain allocations.
///
/// # Errors
/// - [`ErrorKind::Serialization`] — malformed compact token or base64url.
/// - [`ErrorKind::UnsupportedAlgorithm`] — unknown `alg`/`enc` or `crit`.
/// - [`ErrorKind::KeyParsing`] — invalid or mismatched EPK.
/// - [`ErrorKind::Decryption`] — AES-GCM tag failure or AES-KW unwrap failure.
/// - [`ErrorKind::WrongLength`] — IV, tag, or wrapped-key wrong length.
pub fn decrypt(token: &str, key: JweDecryptKey<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let parts = parse_compact(token)?;
    let [header_b64, enc_key_b64, iv_b64, ct_b64, tag_b64] = parts;

    let header_bytes = b64url_decode(header_b64)?;
    let enc_key_bytes = b64url_decode(enc_key_b64)?;
    let iv_bytes = b64url_decode(iv_b64)?;
    let ct_bytes = b64url_decode(ct_b64)?;
    let tag_bytes = b64url_decode(tag_b64)?;

    // serde rejects any unknown alg/enc at this point (no #[serde(other)]).
    let header: JweHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| error_msg(ErrorKind::Serialization, format!("invalid JWE header: {e}")))?;

    header.validate()?;

    validate_key_alg(&header.alg, &key)?;

    if iv_bytes.len() != NONCE_LENGTH {
        return Err(error_msg(
            ErrorKind::WrongLength,
            format!(
                "JWE IV must be {} bytes, got {}",
                NONCE_LENGTH,
                iv_bytes.len()
            ),
        ));
    }
    if tag_bytes.len() != TAG_LENGTH {
        return Err(error_msg(
            ErrorKind::WrongLength,
            format!(
                "JWE authentication tag must be {} bytes, got {}",
                TAG_LENGTH,
                tag_bytes.len()
            ),
        ));
    }

    let nonce: [u8; NONCE_LENGTH] = iv_bytes.try_into().expect("length validated above");
    let tag: [u8; TAG_LENGTH] = tag_bytes.try_into().expect("length validated above");

    let cek_key = recover_cek(&header, &key, &enc_key_bytes)?;

    // AAD = the raw base64url bytes of the first compact segment, exactly as
    // received — we never re-serialize the parsed header. This means JSON field
    // order, whitespace, and any other formatting are preserved verbatim, so
    // tokens from any sender always verify regardless of their serialization style.
    let aad = header_b64.as_bytes();
    let mut plaintext = Zeroizing::new(vec![0u8; ct_bytes.len()]);
    cek_key.decrypt_with_tag(&nonce, aad, tag, &ct_bytes, plaintext.as_mut_slice())?;

    Ok(plaintext)
}

fn validate_key_alg(alg: &AlgAlgorithm, key: &JweDecryptKey<'_>) -> Result<()> {
    let ok = (alg.is_rsa() && matches!(key, JweDecryptKey::Rsa(_)))
        || (alg.is_ecdh() && matches!(key, JweDecryptKey::Ecdh(_)));
    if ok {
        Ok(())
    } else {
        Err(error_msg(
            ErrorKind::UnsupportedAlgorithm,
            "key type does not match the alg header parameter",
        ))
    }
}

/// Recover the CEK from the encrypted-key segment and the protected header.
fn recover_cek(
    header: &JweHeader,
    key: &JweDecryptKey<'_>,
    enc_key_bytes: &[u8],
) -> Result<aead::Key> {
    let apu_bytes: &[u8] = header.apu.as_ref().map_or(&[], |b| b.as_ref());
    let apv_bytes: &[u8] = header.apv.as_ref().map_or(&[], |b| b.as_ref());

    match (&header.alg, key) {
        (
            AlgAlgorithm::RsaOaep256 | AlgAlgorithm::RsaOaep384 | AlgAlgorithm::RsaOaep512,
            JweDecryptKey::Rsa(rsa_key),
        ) => {
            let oaep_alg = header
                .alg
                .to_oaep_algorithm()
                .expect("validate_key_alg ensures this is an RSA variant");
            let mut pt_buf = Zeroizing::new(vec![0u8; rsa_key.key_size_bytes()]);
            let cek_slice = rsa_key.decrypt(oaep_alg, enc_key_bytes, &mut pt_buf)?;

            let cek_bytes = Zeroizing::new(cek_slice.to_vec());
            let cek = aead::Key::new(header.enc.aead_algorithm(), cek_bytes.as_slice())
                .map_err(|e| error_msg(ErrorKind::Decryption, format!("bad CEK length: {e}")))?;
            Ok(cek)
        }

        (AlgAlgorithm::EcdhEs, JweDecryptKey::Ecdh(static_key)) => {
            if !enc_key_bytes.is_empty() {
                return Err(error_msg(
                    ErrorKind::Decryption,
                    "ECDH-ES direct mode requires an empty encrypted-key segment",
                ));
            }
            let shared_secret = ecdh_with_epk(header, static_key)?;

            let mut cek_bytes = Zeroizing::new(vec![0u8; header.enc.key_len()]);
            concat_kdf(
                HashAlg::Sha256,
                shared_secret.as_bytes(),
                &ConcatKdfParams {
                    algorithm_id: header.enc.alg_id(),
                    party_u_info: apu_bytes,
                    party_v_info: apv_bytes,
                },
                &mut cek_bytes,
            )?;

            let cek = aead::Key::new(header.enc.aead_algorithm(), cek_bytes.as_slice())
                .map_err(|e| error_msg(ErrorKind::Decryption, format!("bad CEK length: {e}")))?;
            Ok(cek)
        }

        (
            AlgAlgorithm::EcdhEsA128Kw | AlgAlgorithm::EcdhEsA256Kw,
            JweDecryptKey::Ecdh(static_key),
        ) => {
            let alg = header.alg;
            ecdh_kw_decrypt(header, static_key, enc_key_bytes, apu_bytes, apv_bytes, alg)
        }

        _ => unreachable!("validate_key_alg should have rejected this combination"),
    }
}

/// Derive KEK via ConcatKDF then unwrap the encrypted CEK.
fn ecdh_kw_decrypt(
    header: &JweHeader,
    static_key: &StaticEcdhKey,
    enc_key_bytes: &[u8],
    apu_bytes: &[u8],
    apv_bytes: &[u8],
    alg: AlgAlgorithm,
) -> Result<aead::Key> {
    let kw_alg_id = alg
        .kdf_alg_id()
        .expect("ecdh_kw_decrypt only called for KW variants");
    let kek_len = alg
        .kek_len()
        .expect("ecdh_kw_decrypt only called for KW variants");
    let kw_algorithm = alg
        .kw_algorithm()
        .expect("ecdh_kw_decrypt only called for KW variants");

    let shared_secret = ecdh_with_epk(header, static_key)?;

    let mut kek_bytes = Zeroizing::new(vec![0u8; kek_len]);
    concat_kdf(
        HashAlg::Sha256,
        shared_secret.as_bytes(),
        &ConcatKdfParams {
            algorithm_id: kw_alg_id,
            party_u_info: apu_bytes,
            party_v_info: apv_bytes,
        },
        &mut kek_bytes,
    )?;

    let kek = KeyEncryptionKey::new(kw_algorithm, &kek_bytes)?;
    let expected_cek_len = header.enc.key_len();
    let expected_wrapped_len = expected_cek_len + 8;
    if enc_key_bytes.len() != expected_wrapped_len {
        return Err(error_msg(
            ErrorKind::WrongLength,
            format!(
                "expected {expected_wrapped_len}-byte wrapped CEK for {:?}, got {}",
                header.enc,
                enc_key_bytes.len()
            ),
        ));
    }
    let mut cek_bytes = Zeroizing::new(vec![0u8; expected_cek_len]);
    let cek_slice = kek.unwrap_key(enc_key_bytes, &mut cek_bytes)?;

    let cek = aead::Key::new(header.enc.aead_algorithm(), cek_slice)
        .map_err(|e| error_msg(ErrorKind::Decryption, format!("bad CEK length: {e}")))?;
    Ok(cek)
}

/// Parse the `epk` from the protected header, validate its curve against the
/// static key's curve (not epk's self-declared crv), then perform ECDH.
fn ecdh_with_epk(
    header: &JweHeader,
    static_key: &StaticEcdhKey,
) -> Result<crate::ecdh::SharedSecret> {
    let epk_jwk = header.epk.as_ref().ok_or_else(|| {
        error_msg(
            ErrorKind::KeyParsing,
            "ECDH-ES JWE is missing the epk header parameter",
        )
    })?;

    let (epk_curve, epk_pub) = epk_jwk_to_ecdh_pub(epk_jwk)?;

    // Use the recipient static key's curve as the expected curve — do NOT trust
    // the curve declared inside the attacker-controlled epk JSON.
    if epk_curve != static_key.curve() {
        return Err(error_msg(
            ErrorKind::KeyParsing,
            format!(
                "epk curve {:?} does not match recipient key curve {:?}",
                epk_curve,
                static_key.curve()
            ),
        ));
    }

    static_key.agree_with(&epk_pub)
}
