//! RSA (Rivest–Shamir–Adleman) digital signatures.
//!
//! # Supported Key Sizes
//!
//! - `RSA-2048` - Minimum recommended for new applications (112-bit security)
//! - `RSA-3072` - Medium security (128-bit security)
//! - `RSA-4096` - High security (128-bit security, larger margin)
//! - `RSA-8192` - Very high security (256-bit security, rarely needed)
//!
//! # Padding Schemes
//!
//! - `PKCS#1 v1.5` as described in [RFC8017 Section 8.2]
//! - `PSS` (Probabilistic Signature Scheme) described in [RFC8017 Section 8.1]
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust
//! use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a 2048-bit RSA key pair
//! let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
//!
//! // Sign with PKCS#1 v1.5 padding and SHA-256
//! let message = b"Hello, world!";
//! let mut signature = vec![0u8; 256]; // 2048 bits = 256 bytes
//! let sig = key_pair.sign_pkcs1_sha256(message, &mut signature)?;
//!
//! // Verify the signature
//! key_pair.public_key().verify_pkcs1_sha256(message, sig)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Using PSS Padding (Recommended)
//!
//! ```rust
//! # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
//! let message = b"Important data";
//! let mut signature = vec![0u8; 256];
//!
//! // PSS is recommended for new applications
//! let sig = key_pair.sign_pss_sha256(message, &mut signature)?;
//! key_pair.public_key().verify_pss_sha256(message, sig)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Serialization
//!
//! ```rust
//! # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
//!
//! // Serialize private key to PKCS#8
//! let mut pkcs8_buffer = vec![0u8; 2048];
//! let pkcs8_der = key_pair.to_pkcs8_der(&mut pkcs8_buffer)?;
//!
//! // Serialize public key to SPKI
//! let mut spki_buffer = vec![0u8; 512];
//! let spki_der = key_pair.public_key().to_spki_der(&mut spki_buffer)?;
//!
//! // Load from PKCS#8
//! let loaded_key = KeyPair::from_pkcs8_der(pkcs8_der)?;
//! # Ok(())
//! # }
//! ```
//!
//! [RFC8017 Section 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
//! [RFC8017 Section 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1

#[cfg(test)]
mod tests;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{self, KeyPair as _, RsaKeyPair, RsaSubjectPublicKey};

use crate::digest::HashAlg;
use crate::error::{Error, ErrorKind, Result};
use crate::utils::{key_gen_error, parse_error, serialize_error};

/// RSA key sizes in bits.
///
/// Determines the size of the RSA modulus, which directly affects security level,
/// performance, and signature size.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RsaKeySize {
    /// RSA with 2048-bit modulus (112-bit security).
    Rsa2048,

    /// RSA with 3072-bit modulus (128-bit security).
    Rsa3072,

    /// RSA with 4096-bit modulus (128-bit+ security).
    ///
    /// High security with larger safety margin. Noticeably slower than RSA-2048.
    Rsa4096,

    /// RSA with 8192-bit modulus (256-bit security).
    Rsa8192,
}

impl RsaKeySize {
    /// Returns the key size in bits for this RSA algorithm
    pub fn bits(self) -> usize {
        match self {
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
            RsaKeySize::Rsa8192 => 8192,
        }
    }
}

impl std::fmt::Display for RsaKeySize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaKeySize::Rsa2048 => write!(f, "RSA-2048"),
            RsaKeySize::Rsa3072 => write!(f, "RSA-3072"),
            RsaKeySize::Rsa4096 => write!(f, "RSA-4096"),
            RsaKeySize::Rsa8192 => write!(f, "RSA-8192"),
        }
    }
}

/// RSA signature padding schemes.
///
/// Controls how the message digest is padded before signing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignaturePadding {
    /// PKCS#1 v1.5 padding as defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
    Pkcs1,

    /// PSS (Probabilistic Signature Scheme) padding as defined in
    /// [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
    Pss,
}

impl std::fmt::Display for SignaturePadding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignaturePadding::Pkcs1 => write!(f, "PKCS#1"),
            SignaturePadding::Pss => write!(f, "PSS"),
        }
    }
}

#[derive(Debug)]
struct KeyMaterial {
    keypair: RsaKeyPair,
    key_size: RsaKeySize,
}

impl KeyMaterial {
    fn new(keypair: RsaKeyPair, key_size: RsaKeySize) -> Self {
        Self { keypair, key_size }
    }
}

/// An RSA signing key that can generate signatures.
///
/// # Signature Size
///
/// RSA signatures are always the same size as the modulus:
///
/// - RSA-2048: 256 bytes
/// - RSA-3072: 384 bytes
/// - RSA-4096: 512 bytes
/// - RSA-8192: 1024 bytes
///
/// # Examples
///
/// ```rust
/// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize, SignaturePadding};
/// # use cloud_wallet_crypto::digest::HashAlg;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate key pair
/// let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
///
/// // Sign with custom parameters
/// let message = b"data";
/// let mut signature = vec![0u8; 256];
/// let sig = key_pair.sign(
///     message,
///     HashAlg::Sha256,
///     SignaturePadding::Pss,
///     &mut signature
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct KeyPair {
    material: KeyMaterial,
    public_key: VerifyingKey,
}

impl KeyPair {
    /// Generates a new RSA key pair with the specified key size.
    ///
    /// This uses cryptographically secure random number generation. Key generation
    /// is relatively slow, especially for larger key sizes. As an indication,
    /// an 2048-bit key takes some milliseconds, while an 8192-bit key may take 15 seconds or more.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
    /// // Generate a 3072-bit key for long-term security
    /// let key_pair = KeyPair::generate(RsaKeySize::Rsa3072)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::KeyGeneration` if key generation fails (rare).
    pub fn generate(key_size: RsaKeySize) -> Result<Self> {
        use aws_lc_rs::signature::KeyPair;

        let keypair = RsaKeyPair::generate(key_size.into())
            .map_err(|_| key_gen_error(&key_size.to_string()))?;

        // Extract public key
        let public_key = VerifyingKey {
            key: keypair.public_key().clone(),
        };

        Ok(Self {
            material: KeyMaterial::new(keypair, key_size),
            public_key,
        })
    }

    /// Decodes an RSA signing key from PKCS#8 DER-encoded bytes.
    ///
    /// This format is defined in
    /// [RFC5208](https://datatracker.ietf.org/doc/html/rfc5208#section-5)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
    /// let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
    /// let mut buffer = vec![0u8; 2048];
    /// let pkcs8_der = key_pair.to_pkcs8_der(&mut buffer)?;
    ///
    /// // Load the key from PKCS#8 bytes
    /// let loaded_key = KeyPair::from_pkcs8_der(pkcs8_der)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::KeyParsing` if the input is not valid PKCS#8
    /// - `ErrorKind::UnsupportedAlgorithm` if the key size is not supported
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let keypair =
            RsaKeyPair::from_pkcs8(der).map_err(|_| parse_error("Failed to parse RSA key"))?;

        // Determine key size from the public key modulus bit length
        let key_size = get_key_size(&keypair)?;

        let public_key = VerifyingKey {
            key: keypair.public_key().clone(),
        };

        Ok(Self {
            material: KeyMaterial::new(keypair, key_size),
            public_key,
        })
    }

    /// Decodes an RSA signing key from PKCS#1 DER-encoded bytes.
    ///
    /// # Format
    ///
    /// ```asn1
    /// RSAPrivateKey ::= SEQUENCE {
    ///   version           INTEGER,
    ///   modulus           INTEGER,
    ///   publicExponent    INTEGER,
    ///   privateExponent   INTEGER,
    ///   ...
    /// }
    /// ```
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let keypair =
            RsaKeyPair::from_der(der).map_err(|_| parse_error("Failed to parse RSA key"))?;

        // Determine key size from the public key modulus bit length
        let key_size = get_key_size(&keypair)?;

        let public_key = VerifyingKey {
            key: keypair.public_key().clone(),
        };

        Ok(Self {
            material: KeyMaterial::new(keypair, key_size),
            public_key,
        })
    }

    /// Signs a message with the specified hash algorithm and padding scheme.
    ///
    /// Returns a slice of the `signature` buffer containing the actual signature bytes.
    /// The signature length always equals the modulus length (e.g., 256 bytes for RSA-2048).
    ///
    /// # Buffer Requirements
    ///
    /// The `signature` buffer must be at least as large as the modulus:
    ///
    /// - `RSA-2048`: 256 bytes minimum
    /// - `RSA-3072`: 384 bytes minimum
    /// - `RSA-4096`: 512 bytes minimum
    /// - `RSA-8192`: 1024 bytes minimum
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize, SignaturePadding};
    /// # use cloud_wallet_crypto::digest::HashAlg;
    /// let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
    /// let mut signature = vec![0u8; 256];
    /// let sig = key_pair.sign(
    ///     b"message",
    ///     HashAlg::Sha512,
    ///     SignaturePadding::Pss,
    ///     &mut signature
    /// )?;
    /// assert_eq!(sig.len(), 256);
    /// # Ok(())
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the signature buffer is too small
    /// - `ErrorKind::Signature` if signing fails
    /// - `ErrorKind::UnsupportedAlgorithm` if the hash/padding combination is not supported
    pub fn sign<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        hash_alg: HashAlg,
        padding: SignaturePadding,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let sig_len = self.material.keypair.public_modulus_len();
        let alg = get_signature_alg(hash_alg, padding)?;

        if signature.len() < sig_len {
            return Err(ErrorKind::WrongLength.into());
        }

        self.material
            .keypair
            .sign(alg, &rng, msg.as_ref(), signature)
            .map_err(|_| Error::message(ErrorKind::Signature, "RSA signing failed"))?;
        Ok(&signature[..sig_len])
    }

    /// Signs `msg` with RSASSA-PKCS1-v1_5 padding and SHA-256.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};
    /// # let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
    /// let mut sig_buffer = vec![0u8; 256];
    /// let signature = key_pair.sign_pkcs1_sha256(b"message", &mut sig_buffer)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn sign_pkcs1_sha256<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha256, SignaturePadding::Pkcs1, signature)
    }

    /// Signs `msg` with RSASSA-PKCS1-v1_5 padding and SHA-384.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    pub fn sign_pkcs1_sha384<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha384, SignaturePadding::Pkcs1, signature)
    }

    /// Signs `msg` with RSASSA-PKCS1-v1_5 padding and SHA-512.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    pub fn sign_pkcs1_sha512<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha512, SignaturePadding::Pkcs1, signature)
    }

    /// Signs `msg` with RSASSA-PSS padding and SHA-256.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    pub fn sign_pss_sha256<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha256, SignaturePadding::Pss, signature)
    }

    /// Signs `msg` with RSASSA-PSS padding and SHA-384.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    pub fn sign_pss_sha384<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha384, SignaturePadding::Pss, signature)
    }

    /// Signs `msg` with RSASSA-PSS padding and SHA-512.
    ///
    /// Returns a slice of the signature buffer containing the actual signature.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    pub fn sign_pss_sha512<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha512, SignaturePadding::Pss, signature)
    }

    /// Serializes the private key to PKCS#8 DER format.
    ///
    /// Returns a slice of the output buffer containing the actual encoded bytes.
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the output buffer is too small
    /// - `ErrorKind::Serialization` if encoding fails
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8]> {
        use aws_lc_rs::encoding::Pkcs8V1Der;

        let pkcs8: Pkcs8V1Der<'_> = self
            .material
            .keypair
            .as_der()
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
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// Returns the public modulus len in bytes
    ///
    /// This is also the signature length.
    pub fn modulus_len(&self) -> usize {
        self.material.key_size.bits() / 8
    }
}

/// An RSA public key for signature verification.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    key: RsaSubjectPublicKey,
}

impl VerifyingKey {
    /// Decodes an RSA public verification key from PKCS#1 DER format.
    ///
    /// # Format
    ///
    /// ```asn1
    /// RSAPublicKey ::= SEQUENCE {
    ///   modulus           INTEGER,
    ///   publicExponent    INTEGER
    /// }
    /// ```
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1)
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        RsaSubjectPublicKey::from_der(der)
            .map(|key| Self { key })
            .map_err(|_| Error::from(ErrorKind::KeyParsing))
    }

    /// Verifies a signature for a given message, hash algorithm, and padding scheme.
    ///
    /// The padding scheme must match the one used during signing. Mixing padding
    /// schemes (e.g., signing with PSS, verifying with PKCS#1) will always fail.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize, SignaturePadding};
    /// # use cloud_wallet_crypto::digest::HashAlg;
    /// let key_pair = KeyPair::generate(RsaKeySize::Rsa2048)?;
    /// let mut sig_buf = vec![0u8; 256];
    /// let signature = key_pair.sign(b"Message", HashAlg::Sha512, SignaturePadding::Pss, &mut sig_buf)?;
    ///
    /// key_pair.public_key().verify(
    ///     b"Message",
    ///     HashAlg::Sha512,
    ///     signature,
    ///     SignaturePadding::Pss
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::Signature` if the signature is invalid
    /// - `ErrorKind::UnsupportedAlgorithm` if the hash/padding combination is not supported
    pub fn verify(
        &self,
        message: impl AsRef<[u8]>,
        hash_alg: HashAlg,
        signature: impl AsRef<[u8]>,
        padding: SignaturePadding,
    ) -> Result<()> {
        let alg = get_verification_alg(hash_alg, padding)?;
        let public_key = signature::UnparsedPublicKey::new(alg, self.to_pkcs1_der());

        public_key
            .verify(message.as_ref(), signature.as_ref())
            .map_err(|_| Error::message(ErrorKind::Signature, "RSA signature verification failed"))
    }

    /// Verifies a PKCS#1 v1.5 padded signature with SHA-256.
    ///
    /// `message` is hashed with SHA-256 function.
    pub fn verify_pkcs1_sha256(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha256, signature, SignaturePadding::Pkcs1)
    }

    /// Verifies a PKCS#1 v1.5 padded signature with SHA-384.
    ///
    /// `message` is hashed with SHA-384 function.
    pub fn verify_pkcs1_sha384(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha384, signature, SignaturePadding::Pkcs1)
    }

    /// Verifies a PKCS#1 v1.5 padded signature with SHA-512.
    ///
    /// `message` is hashed with SHA-512 function.
    pub fn verify_pkcs1_sha512(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha512, signature, SignaturePadding::Pkcs1)
    }

    /// Verifies a RSASSA-PSS padded signature with SHA-256.
    ///
    /// `message` is hashed with SHA-256 function.
    pub fn verify_pss_sha256(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha256, signature, SignaturePadding::Pss)
    }

    /// Verifies a RSASSA-PSS padded signature with SHA-384.
    ///
    /// `message` is hashed with SHA-384 function.
    pub fn verify_pss_sha384(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha384, signature, SignaturePadding::Pss)
    }

    /// Verifies a RSASSA-PSS padded signature with SHA-512.
    ///
    /// `message` is hashed with SHA-512 function.
    pub fn verify_pss_sha512(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.verify(message, HashAlg::Sha512, signature, SignaturePadding::Pss)
    }

    /// Serializes the public key to `SubjectPublicKeyInfo` DER format.
    ///
    /// This is the standard X.509 public key format used in certificates.
    /// Returns a slice of the output buffer containing the encoded bytes.
    ///
    /// # Buffer Size
    ///
    /// Approximate sizes (add ~50 bytes margin):
    ///
    /// - RSA-2048: ~294 bytes
    /// - RSA-3072: ~422 bytes
    /// - RSA-4096: ~550 bytes
    /// - RSA-8192: ~1062 bytes
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the output buffer is too small
    /// - `ErrorKind::Serialization` if encoding fails
    pub fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8]> {
        use aws_lc_rs::encoding::PublicKeyX509Der;

        let spki_der: PublicKeyX509Der<'_> = self.key.as_der().map_err(|_| {
            serialize_error("Failed to serialize to SubjectPublicKeyInfo structure")
        })?;

        let spki_bytes = spki_der.as_ref();
        let len = spki_bytes.len();

        if output.len() < len {
            return Err(ErrorKind::WrongLength.into());
        }
        output[..len].copy_from_slice(spki_bytes);
        Ok(&output[..len])
    }

    /// Returns the public key in PKCS#1 DER format.
    ///
    /// This is the RSA-specific public key format.
    pub fn to_pkcs1_der(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Returns the length of the modulus in bytes.
    ///
    /// This is also the signature length.
    pub fn modulus_len(&self) -> usize {
        self.key.modulus_len()
    }
}

fn get_key_size(key_pair: &RsaKeyPair) -> Result<RsaKeySize> {
    let key_size_bits = key_pair.public_modulus_len() * 8;
    match key_size_bits {
        2048 => Ok(RsaKeySize::Rsa2048),
        3072 => Ok(RsaKeySize::Rsa3072),
        4096 => Ok(RsaKeySize::Rsa4096),
        8192 => Ok(RsaKeySize::Rsa8192),
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}

fn get_signature_alg(
    hash_alg: HashAlg,
    padding: SignaturePadding,
) -> Result<&'static signature::RsaSignatureEncoding> {
    use signature::*;

    match (hash_alg, padding) {
        (HashAlg::Sha256, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_SHA256),
        (HashAlg::Sha384, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_SHA384),
        (HashAlg::Sha512, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_SHA512),
        (HashAlg::Sha256, SignaturePadding::Pss) => Ok(&RSA_PSS_SHA256),
        (HashAlg::Sha384, SignaturePadding::Pss) => Ok(&RSA_PSS_SHA384),
        (HashAlg::Sha512, SignaturePadding::Pss) => Ok(&RSA_PSS_SHA512),
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}

fn get_verification_alg(
    hash_alg: HashAlg,
    padding: SignaturePadding,
) -> Result<&'static signature::RsaParameters> {
    use signature::*;

    match (hash_alg, padding) {
        (HashAlg::Sha256, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_2048_8192_SHA256),
        (HashAlg::Sha384, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_2048_8192_SHA384),
        (HashAlg::Sha512, SignaturePadding::Pkcs1) => Ok(&RSA_PKCS1_2048_8192_SHA512),
        (HashAlg::Sha256, SignaturePadding::Pss) => Ok(&RSA_PSS_2048_8192_SHA256),
        (HashAlg::Sha384, SignaturePadding::Pss) => Ok(&RSA_PSS_2048_8192_SHA384),
        (HashAlg::Sha512, SignaturePadding::Pss) => Ok(&RSA_PSS_2048_8192_SHA512),
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}

impl From<RsaKeySize> for aws_lc_rs::rsa::KeySize {
    fn from(key_size: RsaKeySize) -> Self {
        match key_size {
            RsaKeySize::Rsa2048 => aws_lc_rs::rsa::KeySize::Rsa2048,
            RsaKeySize::Rsa3072 => aws_lc_rs::rsa::KeySize::Rsa3072,
            RsaKeySize::Rsa4096 => aws_lc_rs::rsa::KeySize::Rsa4096,
            RsaKeySize::Rsa8192 => aws_lc_rs::rsa::KeySize::Rsa8192,
        }
    }
}
