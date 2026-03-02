//! # ECDSA (Elliptic Curve Digital Signature Algorithm) signing and verification.
//!
//! # Elliptic Curves
//!
//! - `P-256 (secp256r1)` - NIST curve, 256-bit security
//! - `P-384 (secp384r1)` - NIST curve, 384-bit security  
//! - `P-521 (secp521r1)` - NIST curve, 521-bit security
//! - `secp256k1` - Bitcoin/Ethereum curve, 256-bit security
//!
//! # Hash Functions
//!
//! - SHA-256, SHA-384, SHA-512 (SHA-2 family)
//! - SHA3-256, SHA3-384, SHA3-512 (SHA-3 family)
//!
//! ⚠️ Not all curve/hash combinations are valid. Unsupported combinations
//! will return [`ErrorKind::UnsupportedAlgorithm`].
//!
//! # Signature Encodings
//!
//! Two encodings are supported via [`SignatureEncoding`]:
//!
//! - `Asn1` — DER-encoded ECDSA signature (`SEQUENCE { r, s }`)
//! - `Fixed` — Raw fixed-width concatenated `r || s` encoding
//!
//! The caller is responsible for allocating a sufficiently large buffer
//! when using ASN.1 encoding.
//!
//! # Examples
//!
//! ## Basic Signing and Verification
//!
//! ```rust
//! use cloud_wallet_crypto::ecdsa::Curve;
//! use cloud_wallet_crypto::ecdsa::KeyPair;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key pair
//! let key_pair = KeyPair::generate(Curve::P256)?;
//!
//! // Sign a message with SHA-256 (returns fixed 64-byte signature)
//! let message = b"Hello, world!";
//! let signature = key_pair.sign_sha256(message)?;
//!
//! // Verify the signature
//! let public_key = key_pair.public_key();
//! public_key.verify_sha256(message, &signature)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Key Serialization and Deserialization
//!
//! ```rust
//! # use cloud_wallet_crypto::ecdsa::Curve;
//! # use cloud_wallet_crypto::ecdsa::{KeyPair, VerifyingKey};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate(Curve::P256)?;
//!
//! // Serialize private key to PKCS#8 DER
//! let pkcs8_der = key_pair.to_pkcs8_der();
//!
//! // Deserialize from PKCS#8
//! let loaded_key = KeyPair::from_pkcs8_der(pkcs8_der)?;
//!
//! // Export public key in different formats
//! let public_key = key_pair.public_key();
//! let spki_der = public_key.to_spki_der();
//!
//! let mut sec1_uncompressed = [0u8; 65]; // P-256 uncompressed point
//! public_key.to_sec1_uncompressed(&mut sec1_uncompressed)?;
//!
//! let mut sec1_compressed = [0u8; 33]; // P-256 compressed point
//! public_key.to_sec1_compressed(&mut sec1_compressed)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Hash and Encoding
//!
//! ```rust
//! # use cloud_wallet_crypto::ecdsa::Curve;
//! # use cloud_wallet_crypto::ecdsa::{KeyPair, SignatureEncoding};
//! # use cloud_wallet_crypto::digest::HashAlg;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate(Curve::P384)?;
//! let message = b"Important message";
//!
//! // Sign with SHA-384 and ASN.1 encoding
//! let mut buff = [0u8; 150]; // Sufficient for P-384 ASN.1 signature
//! let sig = key_pair.sign(message, HashAlg::Sha384, SignatureEncoding::Asn1, &mut buff)?;
//!
//! // Verify
//! key_pair.public_key().verify(message, sig, HashAlg::Sha384, SignatureEncoding::Asn1)?;
//! # Ok(())
//! # }
//! ```

#[cfg(test)]
mod tests;

use aws_lc_rs::signature::{self, KeyPair as _};
use color_eyre::eyre::eyre;
use pkcs8::{
    self, AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfoRef,
};

use crate::digest::HashAlg;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use crate::utils::{key_gen_error, parse_error, serialize_error};

// Algorithm OIDs
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// EC curve OIDs
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

#[derive(Debug, Clone)]
struct KeyMaterial {
    curve: Curve,
    der: Secret,
}

impl KeyMaterial {
    fn new(curve: Curve, der: impl Into<Secret>) -> Self {
        Self {
            curve,
            der: der.into(),
        }
    }
}

/// Specifies how ECDSA signatures are encoded.
///
/// ECDSA signatures consist of two integers `(r, s)`. This enum controls
/// how they are serialized.
///
/// # Variants
///
/// - [`Asn1`](SignatureEncoding::Asn1): Variable-length DER encoding following
///   [RFC 3279](https://www.rfc-editor.org/rfc/rfc3279). This is the standard
///   format used in X.509 certificates and TLS.
///
/// - [`Fixed`](SignatureEncoding::Fixed): Fixed-length encoding where `r` and `s`
///   are zero-padded and concatenated. This format is more compact.
///
/// # Size Comparison
///
/// | Curve     | ASN.1 (typical) | Fixed     |
/// |:----------|:----------------|:---------|
/// | P-256     | 70-72 bytes     | 64 bytes  |
/// | P-384     | 102-104 bytes   | 96 bytes  |
/// | P-521     | 137-139 bytes   | 132 bytes |
/// | secp256k1 | 70-72 bytes     | 64 bytes  |
///
/// ASN.1 encoding varies by 1-2 bytes depending on the high bits of `r` and `s`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SignatureEncoding {
    /// ASN.1 DER encoding (variable length).
    ///
    /// Structure: `SEQUENCE { r INTEGER, s INTEGER }`
    Asn1,

    /// Fixed-size encoding: `r || s` (concatenated, zero-padded).
    ///
    /// Each component is exactly the curve's field size in bytes.
    Fixed,
}

/// An elliptic curve algorithm
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Curve {
    /// NIST P-256 (secp256r1)
    P256,
    /// NIST P-384 (secp384r1)
    P384,
    /// NIST P-521 (secp521r1)
    P521,
    /// SECG secp256k1 curve
    P256K1,
}

impl Curve {
    /// Returns the key size for this curve
    pub fn key_size(self) -> usize {
        match self {
            Curve::P256 | Curve::P256K1 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// Returns the coordinate size for this curve
    pub fn coordinate_size(self) -> usize {
        self.key_size()
    }

    /// Returns the size of the uncompressed public point for this curve
    pub fn uncompressed_point_size(self) -> usize {
        1 + 2 * self.key_size()
    }

    /// Get the signature size of the signature produced by this curve
    pub fn signature_size(self) -> usize {
        2 * self.key_size()
    }
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Curve::P256 => write!(f, "NIST P-256 (secp256r1)"),
            Curve::P384 => write!(f, "NIST P-384 (secp384r1)"),
            Curve::P521 => write!(f, "NIST P-521 (secp521r1)"),
            Curve::P256K1 => write!(f, "SECG secp256k1"),
        }
    }
}

/// An ECDSA key pair for signing.
///
/// # Key Generation
///
/// Keys are generated with cryptographically secure randomness:
///
/// ```rust
/// # use cloud_wallet_crypto::ecdsa::Curve;
/// # use cloud_wallet_crypto::ecdsa::KeyPair;
/// let key_pair = KeyPair::generate(Curve::P256)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Signing Operations
///
/// Several methods can be used to sign messages:
///
/// - Convenience methods: [`sign_sha256`](KeyPair::sign_sha256), [`sign_sha384`](KeyPair::sign_sha384),
///   [`sign_sha512`](KeyPair::sign_sha512) - Return fixed-size signatures
/// - ASN.1 methods: [`sign_sha256_asn1`](KeyPair::sign_sha256_asn1), etc. - Write ASN.1 signatures to buffers
/// - Generic method: [`sign`](KeyPair::sign) - Full control over hash and encoding
///
/// # Serialization
///
/// Private keys can be serialized to PKCS#8 DER format:
///
/// ```rust
/// # use cloud_wallet_crypto::ecdsa::Curve;
/// # use cloud_wallet_crypto::ecdsa::KeyPair;
/// # let key_pair = KeyPair::generate(Curve::P256)?;
/// let der_bytes = key_pair.to_pkcs8_der();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct KeyPair {
    material: KeyMaterial,
    public_key: VerifyingKey,
}

impl KeyPair {
    /// Generates a new ECDSA key pair for the specified curve.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// // Generate a P-256 key pair
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails (rare).
    pub fn generate(curve: Curve) -> Result<Self> {
        use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};

        // We pick a temporary signing algorithm to generate the key
        let temp_alg = default_signing_alg(curve);
        let keypair = signature::EcdsaKeyPair::generate(temp_alg)
            .map_err(|_| key_gen_error(&curve.to_string()))?;

        // Extract public key as SPKI
        let spki_der: PublicKeyX509Der = keypair
            .public_key()
            .as_der()
            .map_err(|_| serialize_error("Failed to extract public key DER"))?;

        // Extract private key as PKCS#8
        let der = keypair
            .to_pkcs8v1()
            .map_err(|_| serialize_error("Failed to serialize private key to PKCS#8"))?;

        Ok(Self {
            material: KeyMaterial::new(curve, der.as_ref()),
            public_key: VerifyingKey {
                curve,
                spki: spki_der.as_ref().into(),
            },
        })
    }

    /// Creates an ECDSA signing key from PKCS#8 DER-encoded bytes.
    ///
    /// The input must be a valid PKCS#8 `PrivateKeyInfo` structure containing
    /// an EC private key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let der_bytes = key_pair.to_pkcs8_der();
    /// // Load from PKCS#8 DER bytes
    /// let loaded_key = KeyPair::from_pkcs8_der(der_bytes)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::KeyParsing` if the input is not valid PKCS#8
    /// - `ErrorKind::UnsupportedAlgorithm` if the curve is not supported
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        use aws_lc_rs::encoding::AsDer;

        let key_info = PrivateKeyInfo::try_from(der)?;
        let curve = extract_ec_curve(&key_info)?;

        let spki_der = {
            let keypair = signature::EcdsaKeyPair::from_pkcs8(default_signing_alg(curve), der)
                .map_err(|_| parse_error("Failed to parse {curve} key"))?;
            keypair
                .public_key()
                .as_der()
                .map_err(|_| serialize_error("Failed to extract public key DER"))?
        };

        Ok(Self {
            material: KeyMaterial::new(curve, der),
            public_key: VerifyingKey {
                curve,
                spki: spki_der.as_ref().into(),
            },
        })
    }

    /// Signs a message with the specified hash algorithm and encoding.
    ///
    /// The signature is written to the start of `signature` buffer and
    /// the used span is returned.
    ///
    /// # Buffer Size Requirements
    ///
    /// The `signature` buffer must be large enough for the encoding format:
    ///
    /// ## Fixed Encoding
    ///
    /// - P-256: 64 bytes
    /// - P-384: 96 bytes
    /// - P-521: 132 bytes
    /// - secp256k1: 64 bytes
    ///
    /// ## ASN.1 Encoding (maximum sizes)
    ///
    /// - P-256: 72 bytes
    /// - P-384: 104 bytes
    /// - P-521: 139 bytes
    /// - secp256k1: 72 bytes
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::{KeyPair, SignatureEncoding};
    /// # use cloud_wallet_crypto::digest::HashAlg;
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let message = b"Important data";
    /// let mut signature = [0u8; 64]; // P-256 fixed encoding
    ///
    /// let sig = key_pair.sign(
    ///     message,
    ///     HashAlg::Sha256,
    ///     SignatureEncoding::Fixed,
    ///     &mut signature
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the `signature` buffer is too small
    /// - `ErrorKind::Signature` if signing fails (rare)
    /// - `ErrorKind::UnsupportedAlgorithm` if the hash/curve combination is not supported
    pub fn sign<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        hash: HashAlg,
        encoding: SignatureEncoding,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        use aws_lc_rs::rand::SystemRandom;

        let rng = SystemRandom::new();
        let signing_alg = get_signing_algorithm(self.curve(), hash, encoding)?;
        let keypair = signature::EcdsaKeyPair::from_pkcs8(signing_alg, self.material.der.expose())
            .map_err(|_| parse_error(eyre!("Failed to parse {} key", self.curve())))?;

        let sig = keypair
            .sign(&rng, msg.as_ref())
            .map_err(|_| Error::message(ErrorKind::Signature, "Failed to sign message"))?;

        let sig_bytes = sig.as_ref();
        let sig_len = sig_bytes.len();

        // check buffer capacity
        if signature.len() < sig_len {
            return Err(ErrorKind::WrongLength.into());
        }
        signature[..sig_len].copy_from_slice(sig_bytes);
        Ok(&signature[..sig_len])
    }

    /// Signs a message with SHA-256 and returns a fixed 64-byte signature.
    ///
    /// This is a convenience method that uses SHA-256 and the fixed encoding format.
    /// It is equivalent to calling `sign` with `HashAlg::Sha256` and `SignatureEncoding::Fixed`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let message = b"Important data";
    /// let signature: [u8; 64] = key_pair.sign_sha256(message)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn sign_sha256(&self, msg: impl AsRef<[u8]>) -> Result<[u8; 64]> {
        let mut signature = [0u8; 64];
        self.sign(
            msg,
            HashAlg::Sha256,
            SignatureEncoding::Fixed,
            &mut signature,
        )?;
        Ok(signature)
    }

    /// Signs a message with SHA-384 and returns a fixed 96-byte signature.
    ///
    /// This is typically used with P-384 keys. The signature is in fixed
    /// encoding (`r || s`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// let key_pair = KeyPair::generate(Curve::P384)?;
    /// let message = b"Important data";
    /// let signature: [u8; 96] = key_pair.sign_sha384(message)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn sign_sha384(&self, msg: impl AsRef<[u8]>) -> Result<[u8; 96]> {
        let mut signature = [0u8; 96];
        self.sign(
            msg,
            HashAlg::Sha384,
            SignatureEncoding::Fixed,
            &mut signature,
        )?;
        Ok(signature)
    }

    /// Signs a message with SHA-512 and returns a fixed 132-byte signature.
    ///
    /// This is typically used with P-521 keys. The signature is in fixed
    /// encoding (`r || s`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// let key_pair = KeyPair::generate(Curve::P521)?;
    /// let message = b"Important data";
    /// let signature: [u8; 132] = key_pair.sign_sha512(message)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn sign_sha512(&self, msg: impl AsRef<[u8]>) -> Result<[u8; 132]> {
        let mut signature = [0u8; 132];
        self.sign(
            msg,
            HashAlg::Sha512,
            SignatureEncoding::Fixed,
            &mut signature,
        )?;
        Ok(signature)
    }

    /// Signs a message with SHA-256 and writes the ASN.1 DER-encoded signature.
    ///
    /// The signature buffer should be at least 72 bytes for P-256/secp256k1.
    ///
    /// The signature is written to the start of `signature` buffer and
    /// the used span is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::KeyPair;
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let mut signature = [0u8; 72];
    /// let sig = key_pair.sign_sha256_asn1(b"message", &mut signature)?;
    /// assert!(sig.len() >= 70 || sig.len() <= 72);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[inline]
    pub fn sign_sha256_asn1<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha256, SignatureEncoding::Asn1, signature)
    }

    /// Signs a message with SHA-384 and writes the ASN.1 DER-encoded signature.
    ///
    /// The signature buffer should be at least 104 bytes for P-384.
    ///
    /// The signature is written to the start of `signature` buffer and
    /// the used span is returned.
    #[inline]
    pub fn sign_sha384_asn1<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha384, SignatureEncoding::Asn1, signature)
    }

    /// Signs a message with SHA-512 and writes the ASN.1 DER-encoded signature.
    ///
    /// The signature buffer should be at least 139 bytes for P-521.
    ///
    /// The signature is written to the start of `signature` buffer and
    /// the used span is returned.
    #[inline]
    pub fn sign_sha512_asn1<'a>(
        &self,
        msg: impl AsRef<[u8]>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        self.sign(msg, HashAlg::Sha512, SignatureEncoding::Asn1, signature)
    }

    /// Returns the private key in PKCS#8 DER format.
    ///
    /// # ⚠️ Security Warning
    ///
    /// The returned slice exposes the private key material. It should be handled carefully.
    #[inline]
    pub fn to_pkcs8_der(&self) -> &[u8] {
        self.material.der.expose()
    }

    /// Returns the corresponding public key.
    #[inline]
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// Returns the elliptic curve used by this key pair.
    #[inline]
    pub fn curve(&self) -> Curve {
        self.material.curve
    }
}

/// An ECDSA public key for signature verification.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    curve: Curve,
    spki: Box<[u8]>,
}

impl VerifyingKey {
    /// Creates a public key from an uncompressed SEC1/X9.62 point.
    ///
    /// The uncompressed format is `0x04 || X || Y`, where `X` and `Y` are the
    /// coordinates of the elliptic curve point, each padded to the curve's field size.
    ///
    /// # Point Sizes
    ///
    /// | Curve     | Total Size | X Size | Y Size |
    /// |:----------|:----------|:-------|-------:|
    /// | P-256     | 65 bytes  | 32     | 32     |
    /// | P-384     | 97 bytes  | 48     | 48     |
    /// | P-521     | 133 bytes | 66     | 66     |
    /// | secp256k1 | 65 bytes  | 32     | 32     |
    ///
    /// # Errors
    ///
    /// - `ErrorKind::KeyParsing` if the point format is invalid
    pub fn from_x962_uncompressed(curve: Curve, point: &[u8]) -> Result<Self> {
        use pkcs8::der::{AnyRef, Encode, asn1::BitStringRef};
        use pkcs8::spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

        if point.is_empty() {
            return Err(parse_error("Empty point data"));
        }

        if point[0] != 0x04 {
            return Err(parse_error(eyre!(
                "Expected uncompressed point format (0x04), got 0x{:02x}",
                point[0]
            )));
        }

        let expected_len = curve.uncompressed_point_size();
        if point.len() != expected_len {
            return Err(parse_error(eyre!(
                "Invalid point length: expected {} bytes, got {}",
                expected_len,
                point.len()
            )));
        }

        // Get the curve OID
        let curve_oid = match curve {
            Curve::P256 => OID_SECP256R1,
            Curve::P384 => OID_SECP384R1,
            Curve::P521 => OID_SECP521R1,
            Curve::P256K1 => OID_SECP256K1,
        };

        let algorithm = AlgorithmIdentifier {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(AnyRef::from(&curve_oid)),
        };

        // Create SubjectPublicKeyInfo
        let subject_public_key = BitStringRef::from_bytes(point)?;
        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        // Encode to SPKI format
        let mut output = vec![0u8; usize::try_from(spki.encoded_len()?)?];
        spki.encode_to_slice(&mut output)?;
        Ok(Self {
            curve,
            spki: output.into(),
        })
    }

    /// Loads a public key from a `SubjectPublicKeyInfo` DER-encoded public key.
    ///
    /// # Errors
    ///
    /// - `ErrorKind::KeyParsing` if the input is not valid SPKI
    /// - `ErrorKind::UnsupportedAlgorithm` if the curve is not supported
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        use pkcs8::SubjectPublicKeyInfoRef;

        let spki = SubjectPublicKeyInfoRef::try_from(der)?;
        let curve = extract_ec_curve(&spki)?;

        Ok(Self {
            curve,
            spki: der.into(),
        })
    }

    /// Verifies a signature for a given message, hash algorithm, and encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::{KeyPair, SignatureEncoding, VerifyingKey};
    /// # use cloud_wallet_crypto::digest::HashAlg;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let message = b"test";
    /// let signature = key_pair.sign_sha256(message)?;
    /// let mut x962 = [0u8; 65];
    /// let x962_point = key_pair.public_key().to_sec1_uncompressed(&mut x962)?;
    ///
    /// let public_key = VerifyingKey::from_x962_uncompressed(Curve::P256, x962_point)?;
    /// public_key.verify(
    ///     message,
    ///     &signature,
    ///     HashAlg::Sha256,
    ///     SignatureEncoding::Fixed
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// - `ErrorKind::Signature` if the signature is invalid or verification fails
    /// - `ErrorKind::UnsupportedAlgorithm` if the hash/curve combination is not supported
    pub fn verify(
        &self,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        hash: HashAlg,
        encoding: SignatureEncoding,
    ) -> Result<()> {
        let mut point = vec![0u8; self.curve.uncompressed_point_size()];
        self.to_sec1_uncompressed(&mut point)?;
        let verifying_alg = get_verification_algorithm(self.curve(), hash, encoding)?;
        let public_key = signature::UnparsedPublicKey::new(verifying_alg, &point);

        public_key
            .verify(message.as_ref(), signature.as_ref())
            .map_err(|_| Error::message(ErrorKind::Signature, "Failed to verify signature"))?;
        Ok(())
    }

    /// Verifies a fixed-size SHA-256 signature.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_crypto::ecdsa::Curve;
    /// # use cloud_wallet_crypto::ecdsa::{KeyPair, VerifyingKey};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate(Curve::P256)?;
    /// let message = b"test";
    /// let signature = key_pair.sign_sha256(message)?;
    /// let mut x962 = [0u8; 65];
    /// key_pair.public_key().to_sec1_uncompressed(&mut x962)?;
    ///
    /// let public_key = VerifyingKey::from_x962_uncompressed(Curve::P256, &x962)?;
    /// public_key.verify_sha256(message, &signature)?;
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn verify_sha256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(
            message,
            signature,
            HashAlg::Sha256,
            SignatureEncoding::Fixed,
        )
    }

    /// Verifies a fixed-size SHA-384 signature.
    #[inline]
    pub fn verify_sha384(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(
            message,
            signature,
            HashAlg::Sha384,
            SignatureEncoding::Fixed,
        )
    }

    /// Verifies a fixed-size SHA-512 signature.
    #[inline]
    pub fn verify_sha512(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(
            message,
            signature,
            HashAlg::Sha512,
            SignatureEncoding::Fixed,
        )
    }

    /// Verifies an ASN.1 encoded SHA-256 signature.
    #[inline]
    pub fn verify_sha256_asn1(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(message, signature, HashAlg::Sha256, SignatureEncoding::Asn1)
    }

    /// Verifies an ASN.1 encoded SHA-384 signature.
    #[inline]
    pub fn verify_sha384_asn1(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(message, signature, HashAlg::Sha384, SignatureEncoding::Asn1)
    }

    /// Verifies an ASN.1 encoded SHA-512 signature.
    #[inline]
    pub fn verify_sha512_asn1(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(message, signature, HashAlg::Sha512, SignatureEncoding::Asn1)
    }

    /// Returns the public key in `SubjectPublicKeyInfo` DER bytes.
    #[inline]
    pub fn to_spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// Encodes the public key to the uncompressed SEC1/X9.62 format.
    ///
    /// The point bytes is written to the start of `output` buffer
    /// and the used span is returned.
    ///
    /// The output format is `0x04 || X || Y`, where `X` and `Y` are the
    /// coordinates of the EC point.
    ///
    /// # Buffer Size Requirements
    ///
    /// - P-256: 65 bytes
    /// - P-384: 97 bytes
    /// - P-521: 133 bytes
    /// - secp256k1: 65 bytes
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the output buffer is too small
    pub fn to_sec1_uncompressed<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8]> {
        let point_size = self.curve.uncompressed_point_size();
        let output = output.get_mut(..point_size).ok_or(ErrorKind::WrongLength)?;

        // Parse SPKI to extract the point
        let spki = SubjectPublicKeyInfoRef::try_from(self.spki.as_ref())?;

        // The subject public key is a BIT STRING containing the EC point
        let point_bytes = spki.subject_public_key.raw_bytes();

        if point_bytes.is_empty() || point_bytes[0] != 0x04 {
            return Err(parse_error("Invalid EC point format"));
        }
        if point_bytes.len() != self.curve.uncompressed_point_size() {
            return Err(parse_error("Invalid EC point length"));
        }

        output[..point_size].copy_from_slice(point_bytes);
        Ok(&output[..point_size])
    }

    /// Encodes the public key to the compressed SEC1/X9.62 format.
    ///
    /// The point bytes is written to the start of `output` buffer
    /// and the used span is returned.
    ///
    /// The compressed format is `(0x02 or 0x03) || X`, where:
    /// - `0x02`: Y coordinate is even
    /// - `0x03`: Y coordinate is odd
    ///
    /// # Buffer Size Requirements
    ///
    /// - P-256: 33 bytes
    /// - P-384: 49 bytes
    /// - P-521: 67 bytes
    /// - secp256k1: 33 bytes
    ///
    /// # Errors
    ///
    /// - `ErrorKind::WrongLength` if the output buffer is too small
    pub fn to_sec1_compressed<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8]> {
        let coordinate_size = self.curve.coordinate_size();

        let output = output
            .get_mut(..coordinate_size + 1)
            .ok_or(ErrorKind::WrongLength)?;

        let mut uncompressed_point = vec![0u8; self.curve.uncompressed_point_size()];
        self.to_sec1_uncompressed(&mut uncompressed_point)?;

        // Extract X and Y coordinates
        let x = &uncompressed_point[1..1 + coordinate_size];
        let y = &uncompressed_point[1 + coordinate_size..];

        // Determine if Y is even or odd
        let y_is_even = (y[y.len() - 1] & 1) == 0;
        let prefix = if y_is_even { 0x02 } else { 0x03 };

        // Build compressed point: prefix || X
        output[0] = prefix;
        output[1..coordinate_size + 1].copy_from_slice(x);
        Ok(&output[..coordinate_size + 1])
    }

    /// Returns the elliptic curve used by this public key.
    #[inline]
    pub fn curve(&self) -> Curve {
        self.curve
    }
}

fn default_signing_alg(curve: Curve) -> &'static signature::EcdsaSigningAlgorithm {
    use signature::*;

    match curve {
        Curve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        Curve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        Curve::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
        Curve::P256K1 => &ECDSA_P256K1_SHA256_ASN1_SIGNING,
    }
}

fn get_signing_algorithm(
    curve: Curve,
    hash: HashAlg,
    encoding: SignatureEncoding,
) -> Result<&'static signature::EcdsaSigningAlgorithm> {
    use signature::*;

    match (curve, hash, encoding) {
        (Curve::P256, HashAlg::Sha256, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P256_SHA256_ASN1_SIGNING)
        }
        (Curve::P256, HashAlg::Sha256, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P256_SHA256_FIXED_SIGNING)
        }
        (Curve::P384, HashAlg::Sha3_384, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P384_SHA3_384_ASN1_SIGNING)
        }
        (Curve::P384, HashAlg::Sha3_384, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P384_SHA3_384_FIXED_SIGNING)
        }
        (Curve::P384, HashAlg::Sha384, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P384_SHA384_ASN1_SIGNING)
        }
        (Curve::P384, HashAlg::Sha384, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P384_SHA384_FIXED_SIGNING)
        }
        (Curve::P521, HashAlg::Sha3_512, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P521_SHA3_512_ASN1_SIGNING)
        }
        (Curve::P521, HashAlg::Sha3_512, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P521_SHA3_512_FIXED_SIGNING)
        }
        (Curve::P521, HashAlg::Sha512, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P521_SHA512_ASN1_SIGNING)
        }
        (Curve::P521, HashAlg::Sha512, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P521_SHA512_FIXED_SIGNING)
        }
        (Curve::P256K1, HashAlg::Sha3_256, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P256K1_SHA3_256_ASN1_SIGNING)
        }
        (Curve::P256K1, HashAlg::Sha3_256, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P256K1_SHA3_256_FIXED_SIGNING)
        }
        (Curve::P256K1, HashAlg::Sha256, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P256K1_SHA256_ASN1_SIGNING)
        }
        (Curve::P256K1, HashAlg::Sha256, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P256K1_SHA256_FIXED_SIGNING)
        }
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}

fn get_verification_algorithm(
    curve: Curve,
    hash: HashAlg,
    encoding: SignatureEncoding,
) -> Result<&'static signature::EcdsaVerificationAlgorithm> {
    use signature::*;

    match (curve, hash, encoding) {
        (Curve::P256, HashAlg::Sha256, SignatureEncoding::Asn1) => Ok(&ECDSA_P256_SHA256_ASN1),
        (Curve::P256, HashAlg::Sha256, SignatureEncoding::Fixed) => Ok(&ECDSA_P256_SHA256_FIXED),
        (Curve::P384, HashAlg::Sha3_384, SignatureEncoding::Asn1) => Ok(&ECDSA_P384_SHA3_384_ASN1),
        (Curve::P384, HashAlg::Sha3_384, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P384_SHA3_384_FIXED)
        }
        (Curve::P384, HashAlg::Sha384, SignatureEncoding::Asn1) => Ok(&ECDSA_P384_SHA384_ASN1),
        (Curve::P384, HashAlg::Sha384, SignatureEncoding::Fixed) => Ok(&ECDSA_P384_SHA384_FIXED),
        (Curve::P521, HashAlg::Sha3_512, SignatureEncoding::Asn1) => Ok(&ECDSA_P521_SHA3_512_ASN1),
        (Curve::P521, HashAlg::Sha3_512, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P521_SHA3_512_FIXED)
        }
        (Curve::P521, HashAlg::Sha512, SignatureEncoding::Asn1) => Ok(&ECDSA_P521_SHA512_ASN1),
        (Curve::P521, HashAlg::Sha512, SignatureEncoding::Fixed) => Ok(&ECDSA_P521_SHA512_FIXED),
        (Curve::P256K1, HashAlg::Sha3_256, SignatureEncoding::Asn1) => {
            Ok(&ECDSA_P256K1_SHA3_256_ASN1)
        }
        (Curve::P256K1, HashAlg::Sha3_256, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P256K1_SHA3_256_FIXED)
        }
        (Curve::P256K1, HashAlg::Sha256, SignatureEncoding::Asn1) => Ok(&ECDSA_P256K1_SHA256_ASN1),
        (Curve::P256K1, HashAlg::Sha256, SignatureEncoding::Fixed) => {
            Ok(&ECDSA_P256K1_SHA256_FIXED)
        }
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}

/// Trait to abstract over types that have an AlgorithmIdentifier
trait AlgIdentifier {
    fn algorithm(&self) -> AlgorithmIdentifierRef<'_>;
}

impl<'a> AlgIdentifier for PrivateKeyInfo<'a> {
    fn algorithm(&self) -> AlgorithmIdentifierRef<'_> {
        self.algorithm
    }
}

impl<'a> AlgIdentifier for SubjectPublicKeyInfoRef<'a> {
    fn algorithm(&self) -> AlgorithmIdentifierRef<'_> {
        self.algorithm
    }
}

/// Extract EC curve OID from PKCS#8 `PrivateKeyInfo`
fn extract_ec_curve<T: AlgIdentifier>(info: &T) -> Result<Curve> {
    match info.algorithm().oid {
        OID_EC_PUBLIC_KEY => {
            let params = info.algorithm().parameters.ok_or_else(|| {
                Error::message(ErrorKind::KeyParsing, "Missing EC curve parameters")
            })?;

            let curve_oid = ObjectIdentifier::try_from(params)?;

            match curve_oid {
                OID_SECP256R1 => Ok(Curve::P256),
                OID_SECP384R1 => Ok(Curve::P384),
                OID_SECP521R1 => Ok(Curve::P521),
                OID_SECP256K1 => Ok(Curve::P256K1),
                _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
            }
        }
        _ => Err(ErrorKind::UnsupportedAlgorithm.into()),
    }
}
