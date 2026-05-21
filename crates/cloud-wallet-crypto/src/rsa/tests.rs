use super::*;
use crate::digest::HashAlg;

fn sign_verify_cycle(key_size: RsaKeySize, hash_alg: HashAlg, padding: SignaturePadding) {
    let key_pair = KeyPair::generate(key_size).unwrap();
    let public_key = key_pair.public_key();
    let message = b"test message for RSA";
    let mut signature = vec![0u8; key_pair.modulus_len()];

    let sig = key_pair
        .sign(message, hash_alg, padding, &mut signature)
        .unwrap();

    public_key.verify(message, hash_alg, sig, padding).unwrap();

    // Test failure cases
    let wrong_message = b"this is not the original message";
    assert!(
        public_key
            .verify(wrong_message, hash_alg, sig, padding)
            .is_err()
    );

    let other_key = KeyPair::generate(key_size).unwrap();
    assert!(
        other_key
            .public_key()
            .verify(message, hash_alg, sig, padding)
            .is_err()
    );

    let mut corrupted_sig = sig.to_vec();
    corrupted_sig[0] ^= 1;
    assert!(
        public_key
            .verify(message, hash_alg, &corrupted_sig, padding)
            .is_err()
    );
}

#[test]
fn test_sign_verify_rsa2048() {
    sign_verify_cycle(
        RsaKeySize::Rsa2048,
        HashAlg::Sha256,
        SignaturePadding::Pkcs1,
    );
    sign_verify_cycle(RsaKeySize::Rsa2048, HashAlg::Sha256, SignaturePadding::Pss);
    sign_verify_cycle(RsaKeySize::Rsa2048, HashAlg::Sha512, SignaturePadding::Pss);
}

#[test]
#[ignore = "4096 is slow for CI"]
fn test_sign_verify_rsa4096() {
    sign_verify_cycle(RsaKeySize::Rsa4096, HashAlg::Sha512, SignaturePadding::Pss);
}

#[test]
fn test_key_serialization() {
    let key_size = RsaKeySize::Rsa2048;
    let key_pair = KeyPair::generate(key_size).unwrap();
    let message = b"message for serialization test";
    let mut signature = vec![0u8; key_pair.modulus_len()];
    let sig = key_pair.sign_pss_sha256(message, &mut signature).unwrap();

    // PKCS#8 private key
    let mut pkcs8_buf = vec![0u8; 2048];
    let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_buf).unwrap();
    let loaded_pkcs8 = KeyPair::from_pkcs8_der(pkcs8_der).unwrap();
    assert_eq!(loaded_pkcs8.modulus_len(), key_pair.modulus_len());

    // PKCS#1 public key
    let pkcs1_pub_der = key_pair.public_key().to_pkcs1_der();
    let loaded_pkcs1_pub = VerifyingKey::from_pkcs1_der(pkcs1_pub_der).unwrap();
    assert!(loaded_pkcs1_pub.verify_pss_sha256(message, sig).is_ok());
    assert_eq!(
        loaded_pkcs1_pub.modulus_len(),
        key_pair.public_key().modulus_len()
    );
}

#[test]
fn test_from_pkcs1_der() {
    // 2048-bit
    let der_2048 = include_bytes!("../../test_data/rsa2048.der");
    let key_2048 = KeyPair::from_pkcs1_der(der_2048).unwrap();
    assert_eq!(key_2048.modulus_len(), 256);

    // 4096-bit
    let der_4096 = include_bytes!("../../test_data/rsa4096.der");
    let key_4096 = KeyPair::from_pkcs1_der(der_4096).unwrap();
    assert_eq!(key_4096.modulus_len(), 512);

    // 8192-bit
    let der_8192 = include_bytes!("../../test_data/rsa8192.der");
    let key_8192 = KeyPair::from_pkcs1_der(der_8192).unwrap();
    assert_eq!(key_8192.modulus_len(), 1024);
}

#[test]
fn test_from_pkcs8_der() {
    // 2048-bit
    let der_2048 = include_bytes!("../../test_data/rsa2048.pkcs8.der");
    let key_2048 = KeyPair::from_pkcs8_der(der_2048).unwrap();
    assert_eq!(key_2048.modulus_len(), 256);

    // 4096-bit
    let der_4096 = include_bytes!("../../test_data/rsa4096.pkcs8.der");
    let key_4096 = KeyPair::from_pkcs8_der(der_4096).unwrap();
    assert_eq!(key_4096.modulus_len(), 512);

    // 8192-bit
    let der_8192 = include_bytes!("../../test_data/rsa8192.pkcs8.der");
    let key_8192 = KeyPair::from_pkcs8_der(der_8192).unwrap();
    assert_eq!(key_8192.modulus_len(), 1024);
}

#[test]
fn test_sign_buffer_too_small() {
    let key_pair = KeyPair::generate(RsaKeySize::Rsa2048).unwrap();
    let mut signature = vec![0u8; 100]; // need at least 256 bytes
    let err = key_pair
        .sign_pkcs1_sha256(b"test", &mut signature)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongLength);
}

#[test]
fn test_serialization_buffer_too_small() {
    let key_pair = KeyPair::generate(RsaKeySize::Rsa2048).unwrap();

    // PKCS#8
    let mut pkcs8_buf = vec![0u8; 512]; // Too small
    let err = key_pair.to_pkcs8_der(&mut pkcs8_buf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongLength);

    // SPKI
    let mut spki_buf = vec![0u8; 256]; // Too small
    let err = key_pair
        .public_key()
        .to_spki_der(&mut spki_buf)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WrongLength);
}
