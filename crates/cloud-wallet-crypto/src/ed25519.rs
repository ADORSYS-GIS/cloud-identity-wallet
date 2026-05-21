//! # EdDSA (Edwards-curve Digital Signature Algorithm)
//!
//! Ed25519 is a modern digital signature algorithm based on twisted Edwards curves
//! designed to be faster than existing digital signature schemes with strong security.
//!
//! # Examples
//!
//! ## Basic Signing and Verification
//!
//! ```rust
//! use cloud_wallet_crypto::ed25519::KeyPair;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key pair
//! let key_pair = KeyPair::generate()?;
//!
//! // Sign a message (returns 64-byte signature)
//! let message = b"Hello, world!";
//! let signature = key_pair.sign(message);
//!
//! // Verify the signature
//! let public_key = key_pair.public_key();
//! public_key.verify(message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Serialization and Deserialization
//!
//! ```rust
//! # use cloud_wallet_crypto::ed25519::KeyPair;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate()?;
//!
//! // Serialize private key to PKCS#8 DER
//! let mut pkcs8_der = [0u8; 128];
//! let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_der)?;
//!
//! // Deserialize from PKCS#8
//! let loaded_key = KeyPair::from_pkcs8_der(&pkcs8_der)?;
//!
//! // Export public key in different formats
//! let public_key = key_pair.public_key();
//! let spki_der = public_key.to_spki_der();
//!
//! let raw_bytes: [u8; 32] = public_key.to_bytes()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with Existing Keys
//!
//! ```rust
//! use cloud_wallet_crypto::ed25519::{KeyPair, VerifyingKey};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let key_pair = KeyPair::generate()?;
//! # let spki_bytes = key_pair.public_key().to_spki_der();
//! // Load a public key from SPKI bytes
//! let public_key = VerifyingKey::from_spki_der(spki_bytes)?;
//!
//! // Or load from raw 32-byte key
//! # let raw_key: [u8; 32] = key_pair.public_key().to_bytes()?;
//! let public_key = VerifyingKey::from_bytes(&raw_key)?;
//! # Ok(())
//! # }
//! ```

use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair as _};
use pkcs8::{AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfoRef};

use crate::error::{Error, ErrorKind, Result};
use crate::utils::{key_gen_error, parse_error, serialize_error};

// Algorithm OIDs
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

struct KeyMaterial {
    keypair: Ed25519KeyPair,
}

impl KeyMaterial {
    fn new(material: Ed25519KeyPair) -> Self {
        Self { keypair: material }
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial").finish_non_exhaustive()
    }
}

/// An Ed25519 key pair for signing.
pub struct KeyPair {
    material: KeyMaterial,
    public_key: VerifyingKey,
}

impl KeyPair {
    /// Generates a new Ed25519 key pair.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ed25519::KeyPair;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate an Ed25519 key pair
    /// let key_pair = KeyPair::generate()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails (rare).
    pub fn generate() -> Result<Self> {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};

        let keypair =
            signature::Ed25519KeyPair::generate().map_err(|_| key_gen_error("Ed25519"))?;

        // Extract public key as SPKI
        let spki_der: PublicKeyX509Der<'_> = keypair
            .public_key()
            .as_der()
            .map_err(|_| parse_error("Failed to extract public key DER"))?;

        Ok(Self {
            material: KeyMaterial::new(keypair),
            public_key: VerifyingKey {
                spki: spki_der.as_ref().into(),
            },
        })
    }

    /// Creates an Ed25519 signing key from PKCS#8 DER-encoded bytes.
    ///
    /// The input must be a valid PKCS#8 `PrivateKeyInfo` structure containing
    /// an Ed25519 private key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ed25519::KeyPair;
    /// # let key_pair = KeyPair::generate()?;
    /// let mut der_bytes = [0u8; 128];
    /// let der_bytes = key_pair.to_pkcs8_der(&mut der_bytes)?;
    /// // Load from PKCS#8 DER bytes
    /// let loaded_key = KeyPair::from_pkcs8_der(&der_bytes)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// `ErrorKind::KeyParsing` if the input is not valid PKCS#8
    /// or if the key is not Ed25519
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        use aws_lc_rs::encoding::AsDer;

        let key_info = PrivateKeyInfo::try_from(der)?;

        // Verify this is an Ed25519 key
        if key_info.algorithm.oid != OID_ED25519 {
            return Err(parse_error("Not an Ed25519 key"));
        }

        let keypair = signature::Ed25519KeyPair::from_pkcs8(der)
            .map_err(|_| parse_error("Failed to parse Ed25519 key"))?;

        let pub_der = keypair
            .public_key()
            .as_der()
            .map_err(|_| parse_error("Failed to extract public key DER"))?;

        Ok(Self {
            material: KeyMaterial::new(keypair),
            public_key: VerifyingKey {
                spki: pub_der.as_ref().into(),
            },
        })
    }

    /// Signs a message and returns a 64-byte signature.
    ///
    /// Ed25519 uses SHA-512 internally. The signature is always 64 bytes in size.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ed25519::KeyPair;
    /// let key_pair = KeyPair::generate()?;
    /// let message = b"Important data";
    /// let signature: [u8; 64] = key_pair.sign(message);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the message is unable to be signed (extremely rare)
    pub fn sign(&self, msg: impl AsRef<[u8]>) -> [u8; 64] {
        let signature_val = self.material.keypair.sign(msg.as_ref());

        let mut signature = [0u8; 64];
        signature.copy_from_slice(signature_val.as_ref());
        signature
    }

    /// Returns the private key in PKCS#8 DER format.
    ///
    /// # ⚠️ Security Warning
    ///
    /// The returned slice exposes the private key material. It should be handled carefully.
    ///
    /// # Errors
    ///
    /// `ErrorKind::WrongLength` if the `output` buffer is too small
    #[inline]
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8]> {
        let pkcs8 = self
            .material
            .keypair
            .to_pkcs8()
            .map_err(|_| serialize_error("Failed to serialize to PKCS#8"))?;
        let pkcs8_bytes = pkcs8.as_ref();
        let len = pkcs8_bytes.len();

        if output.len() < len {
            return Err(ErrorKind::WrongLength.into());
        }
        output[..len].copy_from_slice(pkcs8_bytes);
        Ok(&output[..len])
    }

    /// Returns the corresponding public key.
    #[inline]
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key for signature verification.
#[derive(Debug)]
pub struct VerifyingKey {
    spki: Box<[u8]>,
}

impl VerifyingKey {
    /// Creates a public key from raw 32-byte key bytes.
    pub fn from_bytes(raw_key: &[u8; 32]) -> Result<Self> {
        use pkcs8::der::{Encode, asn1::BitStringRef};
        use pkcs8::spki::SubjectPublicKeyInfo;

        let algorithm = AlgorithmIdentifierRef {
            oid: OID_ED25519,
            parameters: None,
        };

        // Create SubjectPublicKeyInfo
        let subject_public_key = BitStringRef::from_bytes(raw_key)?;
        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        // Encode to SPKI format
        let mut output = vec![0u8; usize::try_from(spki.encoded_len()?)?];
        spki.encode_to_slice(&mut output)?;
        Ok(Self {
            spki: output.into(),
        })
    }

    /// Loads a public key from a `SubjectPublicKeyInfo` DER-encoded public key.
    ///
    /// # Errors
    ///
    /// - `ErrorKind::KeyParsing` if the input is not valid SPKI
    /// - `ErrorKind::UnsupportedAlgorithm` if the key is not Ed25519
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        use pkcs8::SubjectPublicKeyInfoRef;

        let spki = SubjectPublicKeyInfoRef::try_from(der)?;

        // Verify this is an Ed25519 key
        if spki.algorithm.oid != OID_ED25519 {
            return Err(ErrorKind::UnsupportedAlgorithm.into());
        }

        // Ed25519 public keys should not have algorithm parameters
        if spki.algorithm.parameters.is_some() {
            return Err(parse_error(
                "Ed25519 keys should not have algorithm parameters",
            ));
        }
        Ok(Self { spki: der.into() })
    }

    /// Verifies a signature for a given message.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use cloud_wallet_crypto::ed25519::KeyPair;
    ///
    /// let key_pair = KeyPair::generate()?;
    /// let message = b"test";
    /// let signature = key_pair.sign(message);
    ///
    /// let public_key = key_pair.public_key();
    /// public_key.verify(message, &signature)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::Signature` if the signature is invalid or verification fails
    /// - `ErrorKind::WrongLength` if the signature is not 64 bytes
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<()> {
        let signature_bytes = signature.as_ref();
        if signature_bytes.len() != 64 {
            return Err(ErrorKind::WrongLength.into());
        }

        let raw_key = self.to_bytes()?;
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &raw_key);

        public_key
            .verify(message.as_ref(), signature_bytes)
            .map_err(|_| Error::message(ErrorKind::Signature, "Failed to verify signature"))?;
        Ok(())
    }

    /// Returns the public key in `SubjectPublicKeyInfo` DER bytes.
    #[inline]
    pub fn to_spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// Returns the raw 32 bytes public key.
    pub fn to_bytes(&self) -> Result<[u8; 32]> {
        // Parse SPKI to extract the raw key
        let spki = SubjectPublicKeyInfoRef::try_from(self.spki.as_ref())?;

        // The subject public key is a BIT STRING containing the raw Ed25519 key
        let key_bytes = spki.subject_public_key.raw_bytes();

        if key_bytes.len() != 32 {
            return Err(parse_error("Invalid Ed25519 key length"));
        }

        let mut output = [0u8; 32];
        output.copy_from_slice(key_bytes);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sign_verify_cycle() {
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key();
        let message = b"test message for Ed25519";

        let signature = key_pair.sign(message);

        public_key.verify(message, signature).unwrap();
        let wrong_message = b"this is not the original message";
        assert!(public_key.verify(wrong_message, signature).is_err());

        let other_key = KeyPair::generate().unwrap();
        assert!(other_key.public_key().verify(message, signature).is_err());

        let mut corrupted_signature = signature;
        corrupted_signature[0] ^= 1;
        assert!(public_key.verify(message, corrupted_signature).is_err());

        // Test wrong signature length
        let short_signature = &signature[..63];
        assert_eq!(
            public_key
                .verify(message, short_signature)
                .unwrap_err()
                .kind(),
            ErrorKind::WrongLength
        );
    }

    #[test]
    fn test_key_serialization_pkcs8() {
        let key_pair = KeyPair::generate().unwrap();
        let message = b"message to be signed";
        let signature = key_pair.sign(message);

        // Serialize to PKCS#8 DER
        let mut pkcs8_der_buf = [0u8; 128];
        let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_der_buf).unwrap();

        // Deserialize and verify
        let loaded_key = KeyPair::from_pkcs8_der(pkcs8_der).unwrap();
        loaded_key.public_key().verify(message, signature).unwrap();
    }

    #[test]
    fn test_public_key_serialization() {
        let key_pair = KeyPair::generate().unwrap();
        let message = b"another message";
        let signature = key_pair.sign(message);
        let public_key = key_pair.public_key();

        // SPKI DER
        let spki_der = public_key.to_spki_der();
        let loaded_spki = VerifyingKey::from_spki_der(spki_der).unwrap();
        loaded_spki.verify(message, signature).unwrap();

        // Raw bytes
        let raw_bytes = public_key.to_bytes().unwrap();
        let loaded_raw = VerifyingKey::from_bytes(&raw_bytes).unwrap();
        loaded_raw.verify(message, signature).unwrap();

        // Check that both deserialized keys are the same
        assert_eq!(
            loaded_spki.to_bytes().unwrap(),
            loaded_raw.to_bytes().unwrap()
        );
    }

    #[test]
    fn test_from_pkcs8_der() {
        let pkcs8_der = include_bytes!("../test_data/ed25519-pkcs8-v2.bin");
        let key_pair = KeyPair::from_pkcs8_der(pkcs8_der).unwrap();

        // The public key for this test key is known
        let expected_pub_bytes =
            hex!("de4e8bdcbcef5e9fff0ba11989fec69282bae74fb16ad996acbdddcc0755bc09");

        assert_eq!(
            key_pair.public_key().to_bytes().unwrap(),
            expected_pub_bytes
        );
    }

    #[test]
    fn test_pkcs8_buffer_too_small() {
        let key_pair = KeyPair::generate().unwrap();
        let mut pkcs8_der_buf = [0u8; 32]; // Too small
        let err = key_pair.to_pkcs8_der(&mut pkcs8_der_buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WrongLength);
    }

    #[test]
    fn test_from_invalid_pkcs8() {
        let invalid_der = b"not a valid pkcs8 key";
        let err = KeyPair::from_pkcs8_der(invalid_der).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);
    }

    #[test]
    fn test_from_invalid_spki() {
        let invalid_der = b"not a valid spki key";
        let err = VerifyingKey::from_spki_der(invalid_der).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KeyParsing);
    }
}
