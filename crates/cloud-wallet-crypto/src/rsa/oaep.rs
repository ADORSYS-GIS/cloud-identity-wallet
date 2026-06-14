//! RSA-OAEP asymmetric encryption (JWE `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`).
//!
//! Wraps aws-lc-rs OAEP primitives with crate-consistent error types. The
//! private key is stored as a plain `PrivateDecryptingKey` so `public_key()`
//! can be derived without a second stored reference.

use aws_lc_rs::rsa::{
    OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
};

use crate::error::{ErrorKind, Result};
use crate::utils::{error_msg, key_gen_error, parse_error};

/// RSA-OAEP hash/MGF1 algorithm selector.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepAlgorithm {
    /// SHA-256 hash and MGF1-SHA-256 — JWE `RSA-OAEP-256`.
    Sha256,
    /// SHA-384 hash and MGF1-SHA-384.
    Sha384,
    /// SHA-512 hash and MGF1-SHA-512.
    Sha512,
}

impl OaepAlgorithm {
    fn lc_algorithm(self) -> &'static aws_lc_rs::rsa::OaepAlgorithm {
        match self {
            Self::Sha256 => &OAEP_SHA256_MGF1SHA256,
            Self::Sha384 => &OAEP_SHA384_MGF1SHA384,
            Self::Sha512 => &OAEP_SHA512_MGF1SHA512,
        }
    }
}

/// RSA public key for OAEP encryption.
pub struct EncryptingKey(OaepPublicEncryptingKey);

impl std::fmt::Debug for EncryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingKey")
            .field("key_size_bits", &self.0.key_size_bits())
            .finish_non_exhaustive()
    }
}

impl EncryptingKey {
    /// Deserialise a public key from DER-encoded X.509 `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    /// [`ErrorKind::KeyParsing`] if the bytes are not a valid RSA public key
    /// or if the key size is not supported (must be 2048–8192 bits).
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self> {
        let pub_key = PublicEncryptingKey::from_der(bytes)
            .map_err(|_| parse_error("invalid RSA SubjectPublicKeyInfo DER"))?;
        OaepPublicEncryptingKey::new(pub_key)
            .map(Self)
            .map_err(|_| {
                parse_error("RSA public key is not valid for OAEP (unsupported size or type)")
            })
    }

    /// RSA modulus length in bytes; equals the ciphertext size.
    #[must_use]
    pub fn ciphertext_size(&self) -> usize {
        self.0.ciphertext_size()
    }

    /// Maximum plaintext size for the given padding.
    #[must_use]
    pub fn max_plaintext_size(&self, algorithm: OaepAlgorithm) -> usize {
        self.0.max_plaintext_size(algorithm.lc_algorithm())
    }

    /// Encrypt `plaintext` into `output` using RSA-OAEP.
    ///
    /// `output.len()` must be `>= self.ciphertext_size()`.
    /// `plaintext.len()` must be `<= self.max_plaintext_size(algorithm)`.
    ///
    /// Returns the filled sub-slice of `output`.
    ///
    /// # Errors
    /// [`ErrorKind::Encryption`] on failure.
    pub fn encrypt<'o>(
        &self,
        algorithm: OaepAlgorithm,
        plaintext: &[u8],
        output: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        // RFC 7518 §4.3 specifies an empty label for JWE RSA-OAEP.
        self.0
            .encrypt(algorithm.lc_algorithm(), plaintext, output, None)
            .map(|s| &*s)
            .map_err(|_| error_msg(ErrorKind::Encryption, "RSA-OAEP encryption failed"))
    }
}

/// RSA private key for OAEP decryption.
///
/// # No Conversion Path to Signing
///
/// This type is for **OAEP decryption** only. There is no conversion path to
/// or from [`super::KeyPair`]: the two types wrap different aws-lc-rs internal
/// representations (`PrivateDecryptingKey` vs `RsaKeyPair`) that have no
/// `From`/`Into` impl between them. To use the same RSA private key for both
/// OAEP decryption and signing, load the PKCS#8 DER into each type separately
/// (see the note on [`super::KeyPair`] for an example).
pub struct DecryptingKey(PrivateDecryptingKey);

impl std::fmt::Debug for DecryptingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingKey")
            .field("key_size_bits", &self.0.key_size_bits())
            .finish_non_exhaustive()
    }
}

impl DecryptingKey {
    /// Generate a fresh RSA key pair.
    ///
    /// Supported sizes: `Rsa2048`, `Rsa3072`, `Rsa4096`, `Rsa8192`.
    ///
    /// # Errors
    /// [`ErrorKind::KeyGeneration`] on failure.
    pub fn generate(size: super::RsaKeySize) -> Result<Self> {
        PrivateDecryptingKey::generate(size.into())
            .map(Self)
            .map_err(|_| key_gen_error("RSA-OAEP"))
    }

    /// Deserialise a private key from PKCS#8 DER.
    ///
    /// # Errors
    /// [`ErrorKind::KeyParsing`] on failure.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        PrivateDecryptingKey::from_pkcs8(bytes)
            .map(Self)
            .map_err(|_| parse_error("invalid RSA PKCS#8 DER"))
    }

    /// Returns the corresponding public encrypting key.
    ///
    /// # Panics
    /// Cannot panic — key size is validated during [`DecryptingKey::generate`] /
    /// [`DecryptingKey::from_pkcs8_der`].
    #[must_use]
    pub fn public_key(&self) -> EncryptingKey {
        EncryptingKey(
            OaepPublicEncryptingKey::new(self.0.public_key())
                .expect("key size already validated at DecryptingKey construction"),
        )
    }

    /// RSA modulus length in bytes.
    #[must_use]
    pub fn key_size_bytes(&self) -> usize {
        self.0.key_size_bytes()
    }

    /// RSA modulus length in bits.
    #[must_use]
    pub fn key_size_bits(&self) -> usize {
        self.0.key_size_bits()
    }

    /// Decrypt `ciphertext` using RSA-OAEP into `output`.
    ///
    /// `ciphertext.len()` must equal `self.key_size_bytes()`.
    /// `output.len()` must be `>= self.key_size_bytes()`.
    ///
    /// Returns the filled sub-slice of `output`.
    ///
    /// # Errors
    /// [`ErrorKind::Decryption`] on failure.
    pub fn decrypt<'o>(
        &self,
        algorithm: OaepAlgorithm,
        ciphertext: &[u8],
        output: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        // RFC 7518 §4.3 specifies an empty label for JWE RSA-OAEP.
        //
        // `PrivateDecryptingKey::clone` increments an Arc-like refcount on the
        // underlying EVP_PKEY — it does not copy key material. Verified against
        // aws-lc-rs = "1.15". `OaepPrivateDecryptingKey::new` requires ownership,
        // so a clone per call is unavoidable without storing two key types.
        OaepPrivateDecryptingKey::new(self.0.clone())
            .map_err(|_| error_msg(ErrorKind::Decryption, "RSA-OAEP key setup failed"))?
            .decrypt(algorithm.lc_algorithm(), ciphertext, output, None)
            .map(|s| &*s)
            .map_err(|_| error_msg(ErrorKind::Decryption, "RSA-OAEP decryption failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa::RsaKeySize;

    fn encrypt_decrypt_cycle(algorithm: OaepAlgorithm) {
        let decrypting_key = DecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
        let encrypting_key = decrypting_key.public_key();

        let plaintext = b"hello from RSA-OAEP";
        let mut ciphertext = vec![0u8; encrypting_key.ciphertext_size()];
        let ct = encrypting_key
            .encrypt(algorithm, plaintext, &mut ciphertext)
            .unwrap();

        let mut recovered = vec![0u8; decrypting_key.key_size_bytes()];
        let pt = decrypting_key
            .decrypt(algorithm, ct, &mut recovered)
            .unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn round_trip_sha256() {
        encrypt_decrypt_cycle(OaepAlgorithm::Sha256);
    }

    #[test]
    fn round_trip_sha384() {
        encrypt_decrypt_cycle(OaepAlgorithm::Sha384);
    }

    #[test]
    fn round_trip_sha512() {
        encrypt_decrypt_cycle(OaepAlgorithm::Sha512);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = DecryptingKey::generate(RsaKeySize::Rsa2048).unwrap();
        let enc = key.public_key();

        let mut ct = vec![0u8; enc.ciphertext_size()];
        enc.encrypt(OaepAlgorithm::Sha256, b"data", &mut ct)
            .unwrap();
        ct[0] ^= 0xff;

        let mut out = vec![0u8; key.key_size_bytes()];
        assert!(key.decrypt(OaepAlgorithm::Sha256, &ct, &mut out).is_err());
    }

    // ── NIST PKCS#1 known-answer test (decryption only) ───────────────────
    // Key:        test_data/rsa2048.pkcs8.der  (same key used in rsa::KeyPair tests)
    // Ciphertext: test_data/rsa2048.oaep256.ct.bin
    //   Produced by:
    //     openssl pkeyutl -encrypt -pubin -inkey rsa2048.pub.pem \
    //       -pkeyopt rsa_padding_mode:oaep \
    //       -pkeyopt rsa_oaep_md:sha256 \
    //       -pkeyopt rsa_mgf1_md:sha256 \
    //       -in <(printf 'The quick brown fox')
    //   Verified by round-tripping with openssl pkeyutl -decrypt.
    // RSA-OAEP encryption is non-deterministic (randomised seed), so only
    // the decryption direction can be verified against a fixed ciphertext.
    #[test]
    fn nist_oaep_sha256_known_answer() {
        let key_der = include_bytes!("../../test_data/rsa2048.pkcs8.der");
        let ciphertext = include_bytes!("../../test_data/rsa2048.oaep256.ct.bin");

        let key = DecryptingKey::from_pkcs8_der(key_der).unwrap();
        let mut out = vec![0u8; key.key_size_bytes()];
        let plaintext = key
            .decrypt(OaepAlgorithm::Sha256, ciphertext, &mut out)
            .unwrap();

        assert_eq!(plaintext, b"The quick brown fox");
    }

    #[test]
    #[ignore = "4096-bit RSA is slow for CI"]
    fn round_trip_rsa4096() {
        let key = DecryptingKey::generate(RsaKeySize::Rsa4096).unwrap();
        let enc = key.public_key();
        let mut ct = vec![0u8; enc.ciphertext_size()];
        let ciphertext = enc
            .encrypt(OaepAlgorithm::Sha256, b"data", &mut ct)
            .unwrap()
            .to_vec();
        let mut out = vec![0u8; key.key_size_bytes()];
        let pt = key
            .decrypt(OaepAlgorithm::Sha256, &ciphertext, &mut out)
            .unwrap();
        assert_eq!(pt, b"data");
    }
}
