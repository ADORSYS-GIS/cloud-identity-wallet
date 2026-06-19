//! Integration tests for the JWE encrypt/decrypt pipeline.
//!
//! Covers:
//! - Representative roundtrips across alg × curve × enc combinations.
//! - apu/apv swap detection (asymmetry test).
//! - EPK curve mismatch rejection.
//! - Tampered ciphertext / tag / header.
//! - Malformed compact token.
//! - Unknown crit parameter rejection.
//! - Key type mismatch rejection.
//! - RSA-OAEP-256/384/512 encrypt/decrypt roundtrip.
//! - RFC 7518 Appendix C ConcatKDF anchor.
//!
//! # RSA-OAEP independent anchor — decision note
//!
//! These tests use roundtrips for RSA-OAEP (encrypt-then-decrypt with a
//! freshly-generated key). A JWE-level fixed-token decryption KAT is not
//! included here because:
//!
//! - The RSA-OAEP *primitive* (`rsa::oaep`) is independently anchored by
//!   `nist_oaep_sha256_known_answer` in `rsa/oaep.rs`, which decrypts a
//!   ciphertext produced by `openssl pkeyutl` against a fixed 2048-bit key.
//!   That test covers the exact decrypt path used here.
//!
//! -  The JWE RSA-OAEP path adds framing only: compact serialization,
//!    base64url decoding, JSON header deserialization, and CEK-to-AEAD routing.
//!    All of those components are independently tested (roundtrips, tamper
//!    tests, malformed-token tests). A fixed JWE token would duplicate the
//!    primitive KAT without exercising any new JWE-specific logic.
//!
//! # ConcatKDF / ECDH-ES anchor
//!
//! `concat_kdf_rfc7518_appendix_c_sanity` re-verifies the RFC 7518 Appendix C
//! vector already tested in `kdf.rs`. It is a belt-and-suspenders cross-module
//! check, not a new anchor — the ephemeral-key-per-operation design prevents
//! a full fixed-token ECDH-ES KAT without injecting a fixed ephemeral key,
//! which the API deliberately does not expose.

use crate::aead::TAG_LENGTH;
use crate::ecdh::{EcdhCurve, EcdhPublicKey, StaticEcdhKey};
use crate::error::ErrorKind;
use crate::jwe::{
    AlgAlgorithm, EncAlgorithm, JweDecryptKey, JweEncryptKey, JweHeader, decrypt, encrypt,
};
use crate::jwk::B64;
use crate::rsa::RsaKeySize;
use crate::rsa::oaep::DecryptingKey as RsaDecryptingKey;

fn make_ecdh_pair(curve: EcdhCurve) -> (StaticEcdhKey, EcdhPublicKey) {
    let static_key = StaticEcdhKey::generate(curve).unwrap();
    let mut pub_buf = vec![0u8; curve.public_key_len()];
    let pub_bytes = static_key.public_key_bytes(&mut pub_buf).unwrap();
    let pub_key = EcdhPublicKey::from_bytes(curve, pub_bytes).unwrap();
    (static_key, pub_key)
}

fn ecdh_header(alg: AlgAlgorithm, enc: EncAlgorithm) -> JweHeader {
    JweHeader {
        alg,
        enc,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    }
}

fn ecdh_header_with_party(
    alg: AlgAlgorithm,
    enc: EncAlgorithm,
    apu: &[u8],
    apv: &[u8],
) -> JweHeader {
    JweHeader {
        alg,
        enc,
        epk: None,
        apu: Some(B64::new(apu)),
        apv: Some(B64::new(apv)),
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    }
}

fn ecdh_es_roundtrip(curve: EcdhCurve, enc: EncAlgorithm) {
    let (static_key, pub_key) = make_ecdh_pair(curve);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, enc);
    let plaintext = b"roundtrip test";

    let token = encrypt(header, plaintext, JweEncryptKey::Ecdh(&pub_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(got.as_slice(), plaintext);
}

#[test]
fn roundtrip_ecdh_es_p256_a128gcm() {
    ecdh_es_roundtrip(EcdhCurve::P256, EncAlgorithm::A128Gcm);
}

#[test]
fn roundtrip_ecdh_es_p256_a256gcm() {
    ecdh_es_roundtrip(EcdhCurve::P256, EncAlgorithm::A256Gcm);
}

#[test]
fn roundtrip_ecdh_es_p521_a256gcm() {
    ecdh_es_roundtrip(EcdhCurve::P521, EncAlgorithm::A256Gcm);
}

#[test]
fn roundtrip_ecdh_es_p384_a256gcm() {
    ecdh_es_roundtrip(EcdhCurve::P384, EncAlgorithm::A256Gcm);
}

#[test]
fn roundtrip_ecdh_es_x25519_a256gcm() {
    ecdh_es_roundtrip(EcdhCurve::X25519, EncAlgorithm::A256Gcm);
}

fn ecdh_a128kw_roundtrip(curve: EcdhCurve, enc: EncAlgorithm) {
    let (static_key, pub_key) = make_ecdh_pair(curve);
    let header = ecdh_header(AlgAlgorithm::EcdhEsA128Kw, enc);
    let plaintext = b"kw roundtrip";

    let token = encrypt(header, plaintext, JweEncryptKey::Ecdh(&pub_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(got.as_slice(), plaintext);
}

#[test]
fn roundtrip_ecdh_es_a128kw_p256_a256gcm() {
    ecdh_a128kw_roundtrip(EcdhCurve::P256, EncAlgorithm::A256Gcm);
}

fn ecdh_a256kw_roundtrip(curve: EcdhCurve, enc: EncAlgorithm) {
    let (static_key, pub_key) = make_ecdh_pair(curve);
    let header = ecdh_header(AlgAlgorithm::EcdhEsA256Kw, enc);
    let plaintext = b"a256kw roundtrip";

    let token = encrypt(header, plaintext, JweEncryptKey::Ecdh(&pub_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(got.as_slice(), plaintext);
}

#[test]
fn roundtrip_ecdh_es_a256kw_x25519_a256gcm() {
    ecdh_a256kw_roundtrip(EcdhCurve::X25519, EncAlgorithm::A256Gcm);
}

#[test]
fn roundtrip_rsa_oaep256_a256gcm() {
    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
    let enc_key = dec_key.public_key();

    let header = JweHeader {
        alg: AlgAlgorithm::RsaOaep256,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };
    let plaintext = b"rsa oaep roundtrip";

    let token = encrypt(header, plaintext, JweEncryptKey::Rsa(enc_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Rsa(&dec_key)).unwrap();
    assert_eq!(got.as_slice(), plaintext);
}

#[test]
fn roundtrip_rsa_oaep384_a256gcm() {
    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
    let enc_key = dec_key.public_key();

    let header = JweHeader {
        alg: AlgAlgorithm::RsaOaep384,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };
    let token = encrypt(header, b"test384", JweEncryptKey::Rsa(enc_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Rsa(&dec_key)).unwrap();
    assert_eq!(got.as_slice(), b"test384");
}

#[test]
fn roundtrip_rsa_oaep512_a256gcm() {
    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
    let enc_key = dec_key.public_key();

    let header = JweHeader {
        alg: AlgAlgorithm::RsaOaep512,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };
    let token = encrypt(header, b"test512", JweEncryptKey::Rsa(enc_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Rsa(&dec_key)).unwrap();
    assert_eq!(got.as_slice(), b"test512");
}

/// Encrypt with apu=A, apv=B. Then tamper the header to swap them.
/// Decryption must fail with Decryption error (AEAD tag mismatch) because the
/// AAD (header bytes) has changed, invalidating the GCM tag.
///
/// A simple roundtrip with the same apu/apv cannot catch a swap bug because
/// both sides would compute the same (wrong) KDF output. The asymmetry here
/// comes from verifying the AAD: the header bytes change when apu/apv are swapped.
#[test]
fn apu_apv_swap_fails_aead_verification() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let plaintext = b"swap test";

    let header = ecdh_header_with_party(
        AlgAlgorithm::EcdhEs,
        EncAlgorithm::A256Gcm,
        b"Alice",
        b"Bob",
    );
    let token = encrypt(header, plaintext, JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let parts: Vec<&str> = token.splitn(6, '.').collect();
    assert_eq!(parts.len(), 5);

    use base64ct::{Base64UrlUnpadded, Encoding};
    let header_json_bytes = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: crate::jwe::JweHeader = serde_json::from_slice(&header_json_bytes).unwrap();
    std::mem::swap(&mut hdr.apu, &mut hdr.apv);
    let swapped_json = serde_json::to_string(&hdr).unwrap();
    let swapped_b64 = Base64UrlUnpadded::encode_string(swapped_json.as_bytes());

    let tampered_token = format!(
        "{}.{}.{}.{}.{}",
        swapped_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered_token, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::Decryption,
        "expected Decryption, got {err:?}"
    );
}

/// Verify that apu/apv are bound to the KDF output (direct mode): re-derive
/// CEK with different party info → different KDF output → AEAD failure.
#[test]
fn apu_apv_bound_to_kdf_in_ecdh_es_direct() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::X25519);
    let plaintext = b"kdf binding test";

    let header = ecdh_header_with_party(
        AlgAlgorithm::EcdhEs,
        EncAlgorithm::A128Gcm,
        b"Alice",
        b"Bob",
    );
    let token = encrypt(header, plaintext, JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let header_json_bytes = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: crate::jwe::JweHeader = serde_json::from_slice(&header_json_bytes).unwrap();
    hdr.apv = Some(B64::new(b"Charlie".as_slice()));
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Decryption);
}

/// If the recipient uses a P-384 key but the token has a P-256 epk, decryption
/// must fail with KeyParsing (curve mismatch) rather than silently producing
/// wrong output.
#[test]
fn epk_curve_mismatch_rejected() {
    let (_, p256_pub) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"test", JweEncryptKey::Ecdh(&p256_pub)).unwrap();

    let (p384_static, _) = make_ecdh_pair(EcdhCurve::P384);
    let err = decrypt(&token, JweDecryptKey::Ecdh(&p384_static)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KeyParsing);
}

/// Flipping one bit in the ciphertext body must cause an AEAD tag failure.
#[test]
fn tampered_ciphertext_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"secret", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    assert_eq!(parts.len(), 5);

    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut ct = Base64UrlUnpadded::decode_vec(&parts[3]).unwrap();
    ct[0] ^= 0x01;
    parts[3] = Base64UrlUnpadded::encode_string(&ct);

    let tampered = parts.join(".");
    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Decryption);
}

/// Flipping one bit in the authentication tag must cause AEAD verification failure.
#[test]
fn tampered_tag_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A128Gcm);
    let token = encrypt(header, b"secret", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut tag = Base64UrlUnpadded::decode_vec(&parts[4]).unwrap();
    assert_eq!(tag.len(), TAG_LENGTH);
    tag[0] ^= 0xff;
    parts[4] = Base64UrlUnpadded::encode_string(&tag);

    let tampered = parts.join(".");
    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Decryption);
}

/// Modifying the protected header (changing `alg`) must cause AEAD tag failure
/// because the AAD changes.
#[test]
fn tampered_header_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::X25519);
    let header = ecdh_header(AlgAlgorithm::EcdhEsA128Kw, EncAlgorithm::A128Gcm);
    let token = encrypt(header, b"tamper", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let parts: Vec<&str> = token.split('.').collect();

    // Build a different header with the same alg (to pass structural check) but
    // with a different `kid` value that changes the base64url bytes.
    use base64ct::{Base64UrlUnpadded, Encoding};
    let header_json_bytes = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: crate::jwe::JweHeader = serde_json::from_slice(&header_json_bytes).unwrap();
    hdr.kid = Some("attacker-controlled".to_string());
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    // Changing `kid` alters the header bytes, which changes the AAD.
    // The ECDH agreement and AES-KW unwrap are unaffected (they don't depend
    // on `kid`), so the CEK is correctly recovered — but the AES-GCM open
    // fails because the AAD (first compact segment) no longer matches.
    assert_eq!(err.kind(), ErrorKind::Decryption);
}

#[test]
fn malformed_token_wrong_part_count_rejected() {
    let (static_key, _) = make_ecdh_pair(EcdhCurve::P256);
    let err = decrypt("a.b.c.d", JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Serialization);
    let err = decrypt("a.b.c.d.e.f", JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Serialization);
}

#[test]
fn malformed_base64url_rejected() {
    let (static_key, _) = make_ecdh_pair(EcdhCurve::P256);
    let err = decrypt("!!!.a.b.c.d", JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Serialization);
}

#[test]
fn malformed_header_json_rejected() {
    let (static_key, _) = make_ecdh_pair(EcdhCurve::P256);
    use base64ct::{Base64UrlUnpadded, Encoding};
    let bad_json = Base64UrlUnpadded::encode_string(b"not-json");
    let token = format!("{bad_json}.a.b.c.d");
    let err = decrypt(&token, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Serialization);
}

#[test]
fn unknown_crit_parameter_rejected() {
    let (_, pub_key) = make_ecdh_pair(EcdhCurve::P256);

    let header = JweHeader {
        alg: AlgAlgorithm::EcdhEs,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: Some(vec!["unknown-extension".to_string()]),
    };
    let err = encrypt(header, b"crit test", JweEncryptKey::Ecdh(&pub_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::UnsupportedAlgorithm,
        "expected UnsupportedAlgorithm, got {err:?}"
    );
}

/// Verify that the decrypt path independently rejects an unknown `crit` param
/// even when the token arrives from a non-conforming external sender.
/// validate() runs before the AEAD check in decrypt, so UnsupportedAlgorithm
/// is returned rather than the Decryption error a changed AAD would otherwise cause.
#[test]
fn decrypt_rejects_unknown_crit_in_tampered_token() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::X25519);

    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A128Gcm);
    let token = encrypt(header, b"crit decrypt test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: crate::jwe::JweHeader = serde_json::from_slice(&header_json).unwrap();
    hdr.crit = Some(vec!["unknown-extension".to_string()]);
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

/// encrypt() must reject a header that already has epk set. For RSA variants the
/// caller-supplied epk would be serialised verbatim into the token header; for
/// ECDH-ES variants it would be silently overwritten — both are bugs.
#[test]
fn encrypt_rejects_non_none_epk() {
    let (_, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let fake_epk =
        crate::jwe::compact::epk_bytes_to_jwk(EcdhCurve::P256, pub_key.as_bytes()).unwrap();

    let header = JweHeader {
        alg: AlgAlgorithm::EcdhEs,
        enc: EncAlgorithm::A256Gcm,
        epk: Some(fake_epk),
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };

    let err = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

#[test]
fn encrypt_rejects_empty_crit_array() {
    let (_, pub_key) = make_ecdh_pair(EcdhCurve::P256);

    let header = JweHeader {
        alg: AlgAlgorithm::EcdhEs,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: Some(vec![]),
    };

    let err = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

#[test]
fn encrypt_rejects_registered_param_in_crit() {
    let (_, pub_key) = make_ecdh_pair(EcdhCurve::P256);

    for &param in &[
        "alg", "enc", "epk", "apu", "apv", "kid", "typ", "cty", "crit",
    ] {
        let header = JweHeader {
            alg: AlgAlgorithm::EcdhEs,
            enc: EncAlgorithm::A256Gcm,
            epk: None,
            apu: None,
            apv: None,
            kid: None,
            typ: None,
            cty: None,
            crit: Some(vec![param.to_string()]),
        };
        let err = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::UnsupportedAlgorithm,
            "expected UnsupportedAlgorithm for registered crit param \"{param}\""
        );
    }
}

#[test]
fn key_type_mismatch_rejected_on_encrypt() {
    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
    let rsa_enc_key = dec_key.public_key();
    let (_, ecdh_pub_key) = make_ecdh_pair(EcdhCurve::P256);

    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let err = encrypt(header, b"test", JweEncryptKey::Rsa(rsa_enc_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);

    let header = JweHeader {
        alg: AlgAlgorithm::RsaOaep256,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };
    let err = encrypt(header, b"test", JweEncryptKey::Ecdh(&ecdh_pub_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

#[test]
fn rsa_key_rejected_for_ecdh_alg_on_decrypt() {
    let (_, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
    let err = decrypt(&token, JweDecryptKey::Rsa(&dec_key)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

#[test]
fn roundtrip_empty_plaintext() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A128Gcm);

    let token = encrypt(header, b"", JweEncryptKey::Ecdh(&pub_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(got.as_slice(), b"");
}

// RSA-OAEP with large RSA key (ignored — slow in CI)

#[test]
#[ignore]
fn roundtrip_rsa_oaep256_rsa4096_a256gcm() {
    let dec_key = RsaDecryptingKey::generate(RsaKeySize::Rsa4096).unwrap();
    let enc_key = dec_key.public_key();

    let header = JweHeader {
        alg: AlgAlgorithm::RsaOaep256,
        enc: EncAlgorithm::A256Gcm,
        epk: None,
        apu: None,
        apv: None,
        kid: None,
        typ: None,
        cty: None,
        crit: None,
    };
    let plaintext = b"large rsa key test";
    let token = encrypt(header, plaintext, JweEncryptKey::Rsa(enc_key)).unwrap();
    let got = decrypt(&token, JweDecryptKey::Rsa(&dec_key)).unwrap();
    assert_eq!(got.as_slice(), plaintext);
}

/// Changing the `enc` field in the protected header invalidates the AAD and,
/// for ECDH-ES direct mode, produces the wrong KDF output. Both causes result
/// in an AEAD tag failure.
#[test]
fn tampered_enc_algorithm_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"enc-swap test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: crate::jwe::JweHeader = serde_json::from_slice(&header_json).unwrap();
    hdr.enc = EncAlgorithm::A128Gcm;
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::Decryption,
        "expected Decryption, got {err:?}"
    );
}

/// In KW modes the encrypted-key segment must contain a valid wrapped CEK
/// (≥ 24 bytes). An empty segment is caught by the AES-KW minimum-length check.
#[test]
fn empty_encrypted_key_in_kw_mode_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEsA128Kw, EncAlgorithm::A128Gcm);
    let token = encrypt(header, b"kw-empty-key test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let tampered = format!("{}.{}.{}.{}.{}", parts[0], "", parts[2], parts[3], parts[4]);

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::WrongLength,
        "expected WrongLength, got {err:?}"
    );
}

/// AES-GCM requires exactly 12 bytes (96 bits); both shorter and longer IVs must be rejected.
#[test]
fn iv_wrong_length_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A128Gcm);
    let token = encrypt(header, b"iv-test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();

    for bad_iv in [
        Base64UrlUnpadded::encode_string(&[0u8; 6]),
        Base64UrlUnpadded::encode_string(&[0u8; 16]),
    ] {
        let tampered = format!(
            "{}.{}.{}.{}.{}",
            parts[0], parts[1], bad_iv, parts[3], parts[4]
        );
        let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::WrongLength,
            "expected WrongLength for iv len, got {err:?}"
        );
    }
}

/// This test does not exercise encrypt/decrypt directly but confirms that the
/// ConcatKDF primitive used by ECDH-ES produces the RFC 7518 Appendix C vector.
/// Passing this test anchors the KDF output to the JOSE specification.
/// (The actual KDF roundtrip is tested in kdf.rs — this is a cross-module sanity check.)
#[test]
fn concat_kdf_rfc7518_appendix_c_sanity() {
    use crate::digest::HashAlg;
    use crate::kdf::{ConcatKdfParams, concat_kdf};
    use hex_literal::hex;

    let z = hex!("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");
    let mut output = [0u8; 16];
    concat_kdf(
        HashAlg::Sha256,
        &z,
        &ConcatKdfParams {
            algorithm_id: b"A128GCM",
            party_u_info: b"Alice",
            party_v_info: b"Bob",
        },
        &mut output,
    )
    .unwrap();
    // Expected CEK: "VqqN6vgjbSBcIijNcacQGg" (base64url) — RFC 7518 Appendix C
    assert_eq!(output, hex!("56aa8deaf8236d205c2228cd71a7101a"));
}

//
// Tokens produced OFFLINE by joserfc (an independent JOSE implementation acting
// as the sender), NOT by this crate's own encrypt(). Decrypting them proves our
// compact parsing, base64url, header/epk handling, AAD construction, and
// key-recovery paths interoperate with the wider JOSE ecosystem.
//
// Token files and generation commands: see test_data/PROVENANCE.md.

/// A JWE token whose protected header declares `alg=ECDH-ES` but omits the `epk`
/// field must be rejected with KeyParsing before any ECDH work occurs.
#[test]
fn missing_epk_in_ecdh_es_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
    hdr.as_object_mut().unwrap().remove("epk");
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::KeyParsing,
        "expected KeyParsing, got {err:?}"
    );
}

/// ECDH-ES direct mode requires an empty encrypted-key segment (RFC 7516 §5.2 step 9).
/// A non-empty segment must be rejected immediately with Decryption, before any AES-GCM work.
#[test]
fn non_empty_enc_key_in_ecdh_es_direct_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::P256);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let fake_enc_key = Base64UrlUnpadded::encode_string(&[0xABu8; 24]);
    let tampered = format!(
        "{}.{}.{}.{}.{}",
        parts[0], fake_enc_key, parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::Decryption,
        "expected Decryption, got {err:?}"
    );
}

/// The all-zeros X25519 point is a low-order point; aws-lc-rs rejects it during agreement.
/// An attacker who supplies it as the EPK must receive KeyParsing, not a silent wrong CEK.
#[test]
fn epk_low_order_x25519_rejected() {
    let (static_key, pub_key) = make_ecdh_pair(EcdhCurve::X25519);
    let header = ecdh_header(AlgAlgorithm::EcdhEs, EncAlgorithm::A256Gcm);
    let token = encrypt(header, b"test", JweEncryptKey::Ecdh(&pub_key)).unwrap();

    use base64ct::{Base64UrlUnpadded, Encoding};
    let parts: Vec<&str> = token.splitn(6, '.').collect();
    let header_json = Base64UrlUnpadded::decode_vec(parts[0]).unwrap();
    let mut hdr: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
    hdr["epk"]["x"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&[0u8; 32]));
    let modified_json = serde_json::to_string(&hdr).unwrap();
    let modified_b64 = Base64UrlUnpadded::encode_string(modified_json.as_bytes());

    let tampered = format!(
        "{}.{}.{}.{}.{}",
        modified_b64, parts[1], parts[2], parts[3], parts[4]
    );

    let err = decrypt(&tampered, JweDecryptKey::Ecdh(&static_key)).unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::KeyParsing,
        "expected KeyParsing for low-order EPK, got {err:?}"
    );
}

#[test]
fn interop_rsa_oaep256_a256gcm_external_token() {
    let token = include_str!("../../test_data/interop_rsa_oaep256_a256gcm.jwe").trim();
    let der = include_bytes!("../../test_data/rsa2048.pkcs8.der");
    let dec_key = RsaDecryptingKey::from_pkcs8_der(der).unwrap();

    let plaintext = decrypt(token, JweDecryptKey::Rsa(&dec_key)).unwrap();
    assert_eq!(plaintext.as_slice(), b"interop test vector");
}

#[test]
fn interop_ecdh_es_p256_a256gcm_external_token() {
    let token = include_str!("../../test_data/interop_ecdh_es_a256gcm.jwe").trim();
    let der = include_bytes!("../../test_data/p256_recipient.pkcs8.der");
    let static_key = StaticEcdhKey::from_pkcs8_der(EcdhCurve::P256, der).unwrap();

    let plaintext = decrypt(token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(plaintext.as_slice(), b"ecdh interop");
}

#[test]
fn interop_ecdh_es_a256kw_p256_a256gcm_external_token() {
    let token = include_str!("../../test_data/interop_ecdh_es_a256kw_a256gcm.jwe").trim();
    let der = include_bytes!("../../test_data/p256_recipient.pkcs8.der");
    let static_key = StaticEcdhKey::from_pkcs8_der(EcdhCurve::P256, der).unwrap();

    let plaintext = decrypt(token, JweDecryptKey::Ecdh(&static_key)).unwrap();
    assert_eq!(plaintext.as_slice(), b"ecdh kw interop");
}
