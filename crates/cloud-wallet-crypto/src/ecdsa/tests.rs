use super::*;
use crate::digest::HashAlg;

fn sign_verify_cycle(curve: Curve, hash: HashAlg) {
    // Generate key pair
    let key_pair = KeyPair::generate(curve).unwrap();
    let public_key = key_pair.public_key();
    let message = b"test message for ECDSA";

    // Test with Fixed encoding
    let signature_fixed = match curve {
        Curve::P256 | Curve::P256K1 => {
            let mut sig = [0u8; 64];
            key_pair
                .sign(message, hash, SignatureEncoding::Fixed, &mut sig)
                .unwrap();
            sig.to_vec()
        }
        Curve::P384 => {
            let mut sig = [0u8; 96];
            key_pair
                .sign(message, hash, SignatureEncoding::Fixed, &mut sig)
                .unwrap();
            sig.to_vec()
        }
        Curve::P521 => {
            let mut sig = [0u8; 132];
            key_pair
                .sign(message, hash, SignatureEncoding::Fixed, &mut sig)
                .unwrap();
            sig.to_vec()
        }
    };

    assert!(
        public_key
            .verify(message, &signature_fixed, hash, SignatureEncoding::Fixed)
            .is_ok()
    );

    // Test with Asn1 encoding
    let mut sig_asn1_buf = [0u8; 150];
    let signature_asn1 = key_pair
        .sign(message, hash, SignatureEncoding::Asn1, &mut sig_asn1_buf)
        .unwrap();

    assert!(
        public_key
            .verify(message, signature_asn1, hash, SignatureEncoding::Asn1)
            .is_ok()
    );

    // Test failure cases
    let wrong_message = b"this is not the original message";
    let err = public_key
        .verify(
            wrong_message,
            &signature_fixed,
            hash,
            SignatureEncoding::Fixed,
        )
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);

    let err = public_key
        .verify(wrong_message, signature_asn1, hash, SignatureEncoding::Asn1)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Signature);

    let other_key = KeyPair::generate(curve).unwrap();
    assert!(
        other_key
            .public_key()
            .verify(message, &signature_fixed, hash, SignatureEncoding::Fixed)
            .is_err()
    );
}

#[test]
fn test_sign_verify_p256() {
    sign_verify_cycle(Curve::P256, HashAlg::Sha256);
}

#[test]
fn test_sign_verify_p384() {
    sign_verify_cycle(Curve::P384, HashAlg::Sha384);
}

#[test]
fn test_sign_verify_p521() {
    sign_verify_cycle(Curve::P521, HashAlg::Sha512);
}

#[test]
fn test_sign_verify_p256k1() {
    sign_verify_cycle(Curve::P256K1, HashAlg::Sha256);
}

#[test]
fn test_key_serialization_pkcs8() {
    let curve = Curve::P256;
    let key_pair = KeyPair::generate(curve).unwrap();
    let message = b"message to be signed";
    let signature = key_pair.sign_sha256(message).unwrap();

    // Serialize to PKCS#8 DER
    let pkcs8_der = key_pair.to_pkcs8_der();

    // Deserialize and verify
    let loaded_key = KeyPair::from_pkcs8_der(pkcs8_der).unwrap();
    assert_eq!(loaded_key.curve(), curve);

    let loaded_public_key = loaded_key.public_key();
    assert!(loaded_public_key.verify_sha256(message, &signature).is_ok());
}

#[test]
fn test_public_key_serialization() {
    let curve = Curve::P384;
    let key_pair = KeyPair::generate(curve).unwrap();
    let message = b"message to be signed";
    let signature = key_pair.sign_sha384(message).unwrap();
    let public_key = key_pair.public_key();

    // SPKI DER
    let spki_der = public_key.to_spki_der();
    let loaded_spki = VerifyingKey::from_spki_der(spki_der).unwrap();
    assert_eq!(loaded_spki.curve(), curve);
    assert!(loaded_spki.verify_sha384(message, &signature).is_ok());

    // Uncompressed SEC1
    let mut uncompressed = [0u8; 97];
    public_key.to_sec1_uncompressed(&mut uncompressed).unwrap();
    let loaded_uncompressed = VerifyingKey::from_x962_uncompressed(curve, &uncompressed).unwrap();
    assert_eq!(loaded_uncompressed.curve(), curve);
    assert!(
        loaded_uncompressed
            .verify_sha384(message, &signature)
            .is_ok()
    );
}

#[test]
fn test_load_pkcs8() {
    let der_p256 = include_bytes!("../../test_data/secp256r1.pkcs8.der");
    let key_p256 = KeyPair::from_pkcs8_der(der_p256).unwrap();
    assert_eq!(key_p256.curve(), Curve::P256);

    let der_p384 = include_bytes!("../../test_data/secp384r1.pkcs8.der");
    let key_p384 = KeyPair::from_pkcs8_der(der_p384).unwrap();
    assert_eq!(key_p384.curve(), Curve::P384);
}

#[test]
fn test_unsupported_combinations() {
    let key_pair = KeyPair::generate(Curve::P256).unwrap();
    let mut sig = [0u8; 64];
    let err = key_pair
        .sign(b"test", HashAlg::Sha384, SignatureEncoding::Fixed, &mut sig)
        .unwrap_err();
    // SHA-384 is not supported for P-256
    assert_eq!(err.kind(), ErrorKind::UnsupportedAlgorithm);
}

#[test]
fn test_wrong_buffer_size() {
    let key_pair = KeyPair::generate(Curve::P256).unwrap();
    // Buffer is too small for P-256. Should be at least 64 bytes.
    let mut sig = [0u8; 32];
    let err = key_pair
        .sign(b"test", HashAlg::Sha256, SignatureEncoding::Fixed, &mut sig)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongLength);
}
