//! JWE content encryption (RFC 7516).

use zeroize::Zeroizing;

use crate::aead::{self, NONCE_LENGTH};
use crate::aes_kek::KeyEncryptionKey;
use crate::digest::HashAlg;
use crate::ecdh::{EcdhCurve, EcdhPublicKey, EphemeralEcdhKey, SharedSecret};
use crate::error::{ErrorKind, Result};
use crate::jwk::Jwk;
use crate::kdf::{ConcatKdfParams, concat_kdf};
use crate::rsa::oaep::EncryptingKey as RsaEncryptingKey;
use crate::utils::error_msg;

use super::compact::{b64url_encode, epk_bytes_to_jwk, serialize_header};
use super::header::{AlgAlgorithm, JweHeader};

/// Key supplied by the caller for JWE encryption.
///
/// The variant must match the `alg` field in the [`JweHeader`] passed to
/// [`encrypt`]; a mismatch returns [`ErrorKind::UnsupportedAlgorithm`].
#[non_exhaustive]
pub enum JweEncryptKey<'a> {
    /// RSA public key for RSA-OAEP-256, RSA-OAEP-384, or RSA-OAEP-512.
    Rsa(&'a RsaEncryptingKey),
    /// ECDH recipient static public key for ECDH-ES, ECDH-ES+A128KW, or ECDH-ES+A256KW.
    Ecdh(&'a EcdhPublicKey),
}

impl std::fmt::Debug for JweEncryptKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa(_) => f.debug_tuple("JweEncryptKey::Rsa").finish(),
            Self::Ecdh(k) => f
                .debug_tuple("JweEncryptKey::Ecdh")
                .field(&k.curve())
                .finish(),
        }
    }
}

/// Encrypt `plaintext` and return a compact JWE token (RFC 7516 §7.1).
///
/// `header.epk` must be `None` on entry. It is populated automatically for
/// ECDH-ES variants after the ephemeral key is generated.
///
/// The first compact segment (base64url-encoded protected header) is used as
/// the AAD for AES-GCM content encryption, as specified in RFC 7516 §5.1 step 14.
///
/// # Errors
/// - [`ErrorKind::UnsupportedAlgorithm`] — `epk` is not `None` on entry, `alg` / key-type
///   mismatch, or `crit` validation fails (empty array, registered param listed, unknown param).
/// - [`ErrorKind::Encryption`] — RSA-OAEP or AES-GCM encryption failure.
/// - [`ErrorKind::Serialization`] — header JSON serialization failure.
/// - [`ErrorKind::RandomGeneration`] — RNG failure generating IV or CEK.
/// - [`ErrorKind::KeyGeneration`] — ECDH ephemeral key generation failure.
#[must_use = "the encrypted JWE token must be stored; dropping it means the plaintext is unrecoverable"]
pub fn encrypt(mut header: JweHeader, plaintext: &[u8], key: JweEncryptKey<'_>) -> Result<String> {
    // Callers must leave epk as None. For RSA variants it would be serialised verbatim
    // into the header, leaking key material to every recipient. For ECDH-ES variants
    // it would be silently overwritten.
    if header.epk.is_some() {
        return Err(error_msg(
            ErrorKind::UnsupportedAlgorithm,
            "epk must be None on entry to encrypt; \
             it is set automatically for ECDH-ES variants",
        ));
    }

    validate_key_alg(&header.alg, &key)?;

    header.validate()?;

    let (cek_key, enc_key_bytes) = derive_cek(&mut header, key)?;

    let header_b64 = serialize_header(&header)?;
    let aad = header_b64.as_bytes();

    let mut nonce = [0u8; NONCE_LENGTH];
    crate::rand::fill_bytes(&mut nonce)?;

    let mut ct_buf = plaintext.to_vec();
    let tag = cek_key.encrypt(&nonce, aad, &mut ct_buf)?;

    Ok(format!(
        "{}.{}.{}.{}.{}",
        header_b64,
        b64url_encode(&enc_key_bytes),
        b64url_encode(&nonce),
        b64url_encode(&ct_buf),
        b64url_encode(&tag),
    ))
}

/// Reject mismatched alg / key-type pairs before any crypto work.
fn validate_key_alg(alg: &AlgAlgorithm, key: &JweEncryptKey<'_>) -> Result<()> {
    let ok = (alg.is_rsa() && matches!(key, JweEncryptKey::Rsa(_)))
        || (alg.is_ecdh() && matches!(key, JweEncryptKey::Ecdh(_)));
    if ok {
        Ok(())
    } else {
        Err(error_msg(
            ErrorKind::UnsupportedAlgorithm,
            "key type does not match the alg header parameter",
        ))
    }
}

/// Derive (or generate) the CEK and produce the encrypted-key bytes.
///
/// As a side effect, sets `header.epk` for ECDH-ES variants.
fn derive_cek(header: &mut JweHeader, key: JweEncryptKey<'_>) -> Result<(aead::Key, Vec<u8>)> {
    let apu_bytes: Vec<u8> = header
        .apu
        .as_ref()
        .map_or(Vec::new(), |b| b.as_ref().to_vec());
    let apv_bytes: Vec<u8> = header
        .apv
        .as_ref()
        .map_or(Vec::new(), |b| b.as_ref().to_vec());

    match (&header.alg, key) {
        (
            AlgAlgorithm::RsaOaep256 | AlgAlgorithm::RsaOaep384 | AlgAlgorithm::RsaOaep512,
            JweEncryptKey::Rsa(rsa_key),
        ) => {
            let oaep_alg = header
                .alg
                .to_oaep_algorithm()
                .expect("validate_key_alg ensures this is an RSA variant");
            let cek_len = header.enc.key_len();

            let mut cek_bytes = Zeroizing::new(vec![0u8; cek_len]);
            crate::rand::fill_bytes(&mut cek_bytes)?;

            let mut enc_key_buf = vec![0u8; rsa_key.ciphertext_size()];
            let ct = rsa_key.encrypt(oaep_alg, &cek_bytes, &mut enc_key_buf)?;
            // RSA-OAEP output is always exactly modulus size; ct fills enc_key_buf entirely.
            debug_assert_eq!(ct.len(), enc_key_buf.len());
            let enc_key_bytes = enc_key_buf;

            let cek = aead::Key::new(header.enc.aead_algorithm(), cek_bytes.as_slice())?;
            Ok((cek, enc_key_bytes))
        }

        (AlgAlgorithm::EcdhEs, JweEncryptKey::Ecdh(recipient_pub)) => {
            let (shared_secret, epk_jwk) = ecdh_and_epk(recipient_pub.curve(), recipient_pub)?;
            header.epk = Some(epk_jwk);

            let mut cek_bytes = Zeroizing::new(vec![0u8; header.enc.key_len()]);
            concat_kdf(
                HashAlg::Sha256,
                shared_secret.as_bytes(),
                &ConcatKdfParams {
                    algorithm_id: header.enc.alg_id(),
                    party_u_info: &apu_bytes,
                    party_v_info: &apv_bytes,
                },
                &mut cek_bytes,
            )?;

            let cek = aead::Key::new(header.enc.aead_algorithm(), cek_bytes.as_slice())?;
            Ok((cek, Vec::new()))
        }

        (
            AlgAlgorithm::EcdhEsA128Kw | AlgAlgorithm::EcdhEsA256Kw,
            JweEncryptKey::Ecdh(recipient_pub),
        ) => {
            let alg = header.alg;
            ecdh_kw(header, recipient_pub, &apu_bytes, &apv_bytes, alg)
        }

        _ => unreachable!("unhandled alg/key combination — validate_key_alg should prevent this"),
    }
}

/// Run ECDH and produce the KEK via ConcatKDF, then generate and wrap a fresh CEK.
fn ecdh_kw(
    header: &mut JweHeader,
    recipient_pub: &EcdhPublicKey,
    apu_bytes: &[u8],
    apv_bytes: &[u8],
    alg: AlgAlgorithm,
) -> Result<(aead::Key, Vec<u8>)> {
    let kw_alg_id = alg
        .kdf_alg_id()
        .expect("ecdh_kw only called for KW variants");
    let kek_len = alg.kek_len().expect("ecdh_kw only called for KW variants");
    let kw_algorithm = alg
        .kw_algorithm()
        .expect("ecdh_kw only called for KW variants");

    let (shared_secret, epk_jwk) = ecdh_and_epk(recipient_pub.curve(), recipient_pub)?;
    header.epk = Some(epk_jwk);

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

    let cek_len = header.enc.key_len();
    let mut cek_bytes = Zeroizing::new(vec![0u8; cek_len]);
    crate::rand::fill_bytes(&mut cek_bytes)?;

    let kek = KeyEncryptionKey::new(kw_algorithm, &kek_bytes)?;
    let mut wrapped_buf = vec![0u8; cek_len + 8];
    let wrapped = kek.wrap_key(&cek_bytes, &mut wrapped_buf)?;
    // AES-KW output is always exactly input + 8 bytes; wrapped fills wrapped_buf entirely.
    debug_assert_eq!(wrapped.len(), wrapped_buf.len());
    let enc_key_bytes = wrapped_buf;

    let cek = aead::Key::new(header.enc.aead_algorithm(), cek_bytes.as_slice())?;
    Ok((cek, enc_key_bytes))
}

/// Generate an ephemeral key, capture the public key bytes, then perform ECDH.
fn ecdh_and_epk(curve: EcdhCurve, recipient_pub: &EcdhPublicKey) -> Result<(SharedSecret, Jwk)> {
    let ephemeral = EphemeralEcdhKey::generate(curve)?;

    // Capture the ephemeral public key bytes before consuming the ephemeral key.
    let mut epk_pub_buf = vec![0u8; curve.public_key_len()];
    let epk_pub_bytes = ephemeral.public_key_bytes(&mut epk_pub_buf)?;
    let epk_jwk = epk_bytes_to_jwk(curve, epk_pub_bytes)?;

    let shared_secret = ephemeral.agree(recipient_pub)?;
    Ok((shared_secret, epk_jwk))
}
