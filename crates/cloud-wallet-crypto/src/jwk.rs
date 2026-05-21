//! JSON Web Key (JWK) representation and conversion as defined in
//! [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) and
//! [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).
//!
//! # Overview
//!
//! JWK is a JSON-based format for representing cryptographic keys. It's widely used in:
//! - OAuth 2.0 and OpenID Connect
//! - JSON Web Tokens (JWT)
//! - JOSE (JSON Object Signing and Encryption)
//! - API authentication and authorization
//!
//! # Supported Key Types
//!
//! - `ECDSA`: P-256, P-384, P-521, secp256k1
//! - `EdDSA`: Ed25519
//! - `RSA`: 2048, 3072, 4096, 8192 bits
//!
//! # Examples
//!
//! ## Converting Keys to JWK
//!
//! ```rust
//! use cloud_wallet_crypto::ecdsa::{KeyPair, Curve};
//! use cloud_wallet_crypto::jwk::Jwk;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate an ECDSA key pair
//! let key_pair = KeyPair::generate(Curve::P256)?;
//!
//! // Convert to JWK (public key only)
//! let jwk = Jwk::try_from(&key_pair)?;
//!
//! // Serialize to JSON
//! let json = serde_json::to_string_pretty(&jwk)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Converting JWK to Verifying Key
//!
//! ```rust
//! use cloud_wallet_crypto::ecdsa::VerifyingKey;
//! use cloud_wallet_crypto::jwk::Jwk;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse JWK from JSON
//! let jwk_json = r#"{
//!   "kty": "EC",
//!   "crv": "P-256",
//!   "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
//!   "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
//! }"#;
//!
//! let jwk: Jwk = serde_json::from_str(jwk_json)?;
//!
//! // Convert to verifying key
//! let verifying_key = VerifyingKey::try_from(&jwk)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with JWK Sets
//!
//! ```rust
//! use cloud_wallet_crypto::jwk::{JwkSet, Jwk};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse a JWK Set (common in OAuth/OIDC discovery)
//! let jwks_json = r#"{
//!   "keys": [
//!     {
//!       "kty": "EC",
//!       "crv": "P-256",
//!       "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
//!       "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
//!       "kid": "key-1"
//!     }
//!   ]
//! }"#;
//!
//! let jwks: JwkSet = serde_json::from_str(jwks_json)?;
//!
//! // Find key by ID
//! let key = jwks.keys.iter()
//!     .find(|k| k.prm.kid.as_deref() == Some("key-1"));
//! # Ok(())
//! # }
//! ```
//!
//! ## Adding Metadata to JWK
//!
//! ```rust
//! # use cloud_wallet_crypto::ecdsa::{KeyPair, Curve};
//! # use cloud_wallet_crypto::jwk::{Jwk, Parameters, Algorithm, Signing, KeyUse};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let key_pair = KeyPair::generate(Curve::P256)?;
//! let mut jwk = Jwk::try_from(&key_pair)?;
//!
//! // Add metadata
//! jwk.prm.kid = Some("my-key".to_string());
//! jwk.prm.alg = Some(Algorithm::Signing(Signing::Es256));
//! jwk.prm.key_use = Some(KeyUse::Signing);
//!
//! let json = serde_json::to_string_pretty(&jwk)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Public Keys Only
//!
//! The current implementation only exports public keys to JWK format.
//! Private keys are never included, even when converting from a key pair.
//!
//! ## Key Validation
//!
//! When importing keys from JWK:
//! - Coordinate lengths are validated
//! - Curve parameters are checked
//! - Invalid keys are rejected with appropriate errors
//!
//! # Format Details
//!
//! ## Base64URL Encoding
//!
//! JWK uses base64url encoding (RFC 4648 §5) without padding for binary data.
//! This is handled automatically by the [`B64`] type.
//!
//! ## ECDSA Keys
//!
//! EC keys are represented as:
//! ```json
//! {
//!   "kty": "EC",
//!   "crv": "P-256",
//!   "x": "<base64url-encoded-x-coordinate>",
//!   "y": "<base64url-encoded-y-coordinate>"
//! }
//! ```
//!
//! ## EdDSA Keys
//!
//! Ed25519 keys are represented as:
//! ```json
//! {
//!   "kty": "OKP",
//!   "crv": "Ed25519",
//!   "x": "<base64url-encoded-public-key>"
//! }
//! ```
//!
//! ## RSA Keys
//!
//! RSA keys are represented as:
//! ```json
//! {
//!   "kty": "RSA",
//!   "n": "<base64url-encoded-modulus>",
//!   "e": "<base64url-encoded-exponent>"
//! }
//! ```

mod b64;
#[cfg(test)]
mod tests;

pub use crate::jwk::b64::B64;

use std::collections::BTreeSet;

use crate::ecdsa::{KeyPair as EcdsaKeyPair, VerifyingKey as EcdsaVerifyingKey};
use crate::ed25519::{KeyPair as Ed25519KeyPair, VerifyingKey as Ed25519VerifyingKey};
use crate::error::{Error, ErrorKind, Result};
use crate::rsa::{KeyPair as RsaKeyPair, VerifyingKey as RsaVerifyingKey};
use crate::secret::Secret;
use crate::utils::error_msg;

use num_bigint::Sign;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use simple_asn1 as asn1;

/// A JSON Web Key as defined in [RFC 7517 Section 4].
///
/// A JWK represents a cryptographic key in JSON format. It consists of key material
/// and optional metadata (algorithm, key ID, usage constraints, etc.).
///
/// # Examples
///
/// ## Parse from JSON
///
/// ```
/// use cloud_wallet_crypto::jwk::Jwk;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///   "kty": "EC",
///   "crv": "P-256",
///   "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
///   "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
///   "kid": "my-key-1"
/// }"#;
///
/// let jwk: Jwk = serde_json::from_str(json)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Create from key pair
///
/// ```rust
/// # use cloud_wallet_crypto::ecdsa::{KeyPair, Curve};
/// # use cloud_wallet_crypto::jwk::Jwk;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let key_pair = KeyPair::generate(Curve::P256)?;
/// let jwk = Jwk::try_from(&key_pair)?;
/// let json = serde_json::to_string(&jwk)?;
/// # Ok(())
/// # }
/// ```
///
/// [RFC 7517 Section 4]: https://datatracker.ietf.org/doc/html/rfc7517#section-4
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// The cryptographic key material.
    #[serde(flatten)]
    pub key: Key,

    /// The key parameters.
    #[serde(flatten)]
    pub prm: Parameters,
}

/// A set of JSON Web Keys as defined in [RFC7517 Section 5].
///
/// [RFC7517 Section 5]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwkSet {
    /// The keys in the set.
    pub keys: Vec<Jwk>,
}

/// A key type that can be contained in a JWK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", tag = "kty")]
#[non_exhaustive]
pub enum Key {
    /// An elliptic-curve key.
    Ec(Ec),

    /// An RSA key.
    Rsa(Rsa),

    /// A symmetric octet key.
    #[serde(rename = "oct")]
    Oct(Oct),

    /// An octet key pair (EdDSA, X25519, X448).
    Okp(Okp),
}

/// An elliptic curve key for ECDSA signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ec {
    /// The elliptic curve identifier.
    pub crv: Curve,

    /// The public x coordinate (base64url-encoded).
    pub x: B64,

    /// The public y coordinate (base64url-encoded).
    pub y: B64,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

/// Elliptic curves supported for ECDSA.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Curve {
    /// NIST P-256 (secp256r1).
    #[serde(rename = "P-256")]
    P256,

    /// NIST P-384 (secp384r1).
    #[serde(rename = "P-384")]
    P384,

    /// NIST P-521 (secp521r1).
    #[serde(rename = "P-521")]
    P521,

    /// secp256k1 (Bitcoin/Ethereum).
    #[serde(rename = "secp256k1")]
    P256K1,
}

/// An RSA key for signatures and encryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rsa {
    /// The RSA modulus - base64url-encoded.
    pub n: B64,

    /// The RSA public exponent - base64url-encoded.
    pub e: B64,

    /// The RSA private key material.
    #[serde(skip_serializing_if = "Option::is_none", default, flatten)]
    pub prv: Option<RsaPrivate>,
}

/// RSA private key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPrivate {
    /// The RSA private exponent.
    pub d: Secret,

    /// Optional CRT parameters for faster RSA operations.
    #[serde(skip_serializing_if = "Option::is_none", default, flatten)]
    pub opt: Option<RsaOptional>,
}

/// Optional RSA private key components for CRT optimization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaOptional {
    /// The first prime factor.
    pub p: Secret,

    /// The second prime factor.
    pub q: Secret,

    /// The first CRT exponent.
    pub dp: Secret,

    /// The second CRT exponent.
    pub dq: Secret,

    /// The CRT coefficient.
    pub qi: Secret,

    /// Additional prime factors for multi-prime RSA.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub oth: Vec<RsaOtherPrimes>,
}

/// Additional prime factors for multi-prime RSA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaOtherPrimes {
    /// The additional prime factor.
    pub r: Secret,

    /// The CRT exponent.
    pub d: Secret,

    /// The CRT coefficient.
    pub t: Secret,
}

/// A symmetric octet key for encryption or HMAC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oct {
    /// The symmetric key bytes (base64url-encoded).
    pub k: Secret,
}

/// An octet key pair for CFRG curves, as defined in [RFC 8037].
///
/// [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okp {
    /// The CFRG curve identifier.
    pub crv: OkpCurve,

    /// The public key (base64url-encoded).
    pub x: B64,

    /// The private key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub d: Option<Secret>,
}

/// CFRG (Crypto Forum Research Group) curves for OKP keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OkpCurve {
    /// Ed25519 - Edwards curve for signatures.
    Ed25519,

    /// Ed448 - Edwards curve for signatures.
    Ed448,

    /// X25519 - Montgomery curve for key agreement.
    X25519,

    /// X448 - Montgomery curve for key agreement.
    X448,
}

/// JWK metadata parameters unrelated to the key material itself.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameters {
    /// The algorithm intended for use with this key.
    #[serde(default)]
    pub alg: Option<Algorithm>,

    /// Key identifier - unique within a key set.
    #[serde(default)]
    pub kid: Option<String>,

    /// Key usage - signing or encryption.
    #[serde(default, rename = "use")]
    pub key_use: Option<KeyUse>,

    /// Permitted key operations.
    #[serde(default, rename = "key_ops")]
    pub ops: Option<BTreeSet<Operations>>,

    /// URL of X.509 certificate for this key.
    #[serde(default)]
    pub x5u: Option<url::Url>,

    /// X.509 certificate chain (DER, base64-encoded).
    #[serde(default)]
    pub x5c: Option<Vec<B64<base64ct::Base64>>>,

    /// X.509 certificate thumbprints.
    #[serde(flatten)]
    pub x5t: Thumbprint,
}

/// Key usage indicator.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyUse {
    /// Key is intended for encryption/decryption operations.
    #[serde(rename = "enc")]
    Encryption,

    /// Key is intended for signing/verification operations.
    #[serde(rename = "sig")]
    Signing,
}

/// Permitted cryptographic operations for a key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum Operations {
    Decrypt,
    DeriveBits,
    DeriveKey,
    Encrypt,
    Sign,
    UnwrapKey,
    Verify,
    WrapKey,
}

/// X.509 certificate thumbprints.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbprint {
    /// SHA-1 thumbprint (legacy, not recommended).
    #[serde(rename = "x5t", default)]
    pub s1: Option<B64>,

    /// SHA-256 thumbprint (recommended).
    #[serde(rename = "x5t#S256", default)]
    pub s256: Option<B64>,
}

/// Algorithm types that can be specified in JWK metadata.
///
/// Currently only signing algorithms are represented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// Algorithms for digital signatures and MACs.
    Signing(Signing),
}

impl From<Signing> for Algorithm {
    #[inline(always)]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

/// Digital signature algorithms as defined in [RFC 7518 Section 3.1].
///
/// These algorithms are used for signing and verifying JSON Web Signatures (JWS).
///
/// [RFC 7518 Section 3.1]: https://www.rfc-editor.org/rfc/rfc7518#section-3.1
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Signing {
    /// EdDSA signature algorithms (Optional)
    #[serde(rename = "EdDSA")]
    EdDsa,

    /// ECDSA using P-256 and SHA-256 (Recommended+)
    Es256,

    /// ECDSA using secp256k1 curve and SHA-256 (Optional)
    Es256K,

    /// ECDSA using P-384 and SHA-384 (Optional)
    Es384,

    /// ECDSA using P-521 and SHA-512 (Optional)
    Es512,

    /// HMAC using SHA-256 (Required)
    Hs256,

    /// HMAC using SHA-384 (Optional)
    Hs384,

    /// HMAC using SHA-512 (Optional)
    Hs512,

    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (Optional)
    Ps256,

    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (Optional)
    Ps384,

    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (Optional)
    Ps512,

    /// RSASSA-PKCS1-v1_5 using SHA-256 (Recommended)
    Rs256,

    /// RSASSA-PKCS1-v1_5 using SHA-384 (Optional)
    Rs384,

    /// RSASSA-PKCS1-v1_5 using SHA-512 (Optional)
    Rs512,

    /// No digital signature or MAC performed (Optional)
    #[serde(rename = "none")]
    Null,
}

impl std::fmt::Display for Signing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.serialize(f)
    }
}

impl From<Ec> for Key {
    #[inline(always)]
    fn from(key: Ec) -> Self {
        Self::Ec(key)
    }
}

impl From<Rsa> for Key {
    #[inline(always)]
    fn from(key: Rsa) -> Self {
        Self::Rsa(key)
    }
}

impl From<Oct> for Key {
    #[inline(always)]
    fn from(key: Oct) -> Self {
        Self::Oct(key)
    }
}

impl From<Okp> for Key {
    #[inline(always)]
    fn from(key: Okp) -> Self {
        Self::Okp(key)
    }
}

impl TryFrom<&EcdsaKeyPair> for Jwk {
    type Error = Error;

    /// Converts an ECDSA key pair to a JWK containing only the public key.
    fn try_from(key_pair: &EcdsaKeyPair) -> Result<Self> {
        let curve = key_pair.curve();
        let public_key = key_pair.public_key();

        // Get the uncompressed point coordinates
        let mut uncompressed_point = vec![0u8; curve.uncompressed_point_size()];
        let point_bytes = public_key.to_sec1_uncompressed(&mut uncompressed_point)?;

        // Extract X and Y coordinates from uncompressed point (0x04 || X || Y)
        let uncompressed_len = curve.uncompressed_point_size();
        let coordinate_size = curve.coordinate_size();
        if point_bytes.len() != uncompressed_len {
            return Err(error_msg(
                ErrorKind::KeyParsing,
                "Invalid uncompressed point format",
            ));
        }

        let x = B64::new(&point_bytes[1..1 + coordinate_size]);
        let y = B64::new(&point_bytes[1 + coordinate_size..uncompressed_len]);
        let crv = curve.into();
        let ec_key = Ec { crv, x, y, d: None };

        Ok(Jwk {
            key: Key::from(ec_key),
            prm: Parameters::default(),
        })
    }
}

impl TryFrom<&Jwk> for EcdsaVerifyingKey {
    type Error = Error;

    /// Converts a JWK public key to an ECDSA verifying key.
    fn try_from(jwk: &Jwk) -> Result<Self> {
        match &jwk.key {
            Key::Ec(ec_key) => {
                let curve: crate::ecdsa::Curve = ec_key.crv.into();

                // Reconstruct uncompressed point: 0x04 || X || Y
                let coordinate_size = curve.coordinate_size();
                let uncompressed_len = curve.uncompressed_point_size();
                let mut uncompressed_point = vec![0u8; uncompressed_len];
                uncompressed_point[0] = 0x04;

                if ec_key.x.len() != coordinate_size || ec_key.y.len() != coordinate_size {
                    return Err(error_msg(
                        ErrorKind::WrongLength,
                        "Invalid coordinate length",
                    ));
                }

                uncompressed_point[1..1 + coordinate_size].copy_from_slice(&ec_key.x);
                uncompressed_point[1 + coordinate_size..uncompressed_len]
                    .copy_from_slice(&ec_key.y);

                EcdsaVerifyingKey::from_x962_uncompressed(curve, &uncompressed_point)
            }
            _ => Err(Error::from(ErrorKind::UnsupportedAlgorithm)),
        }
    }
}

impl TryFrom<&Ed25519KeyPair> for Jwk {
    type Error = Error;

    /// Converts an Ed25519 key pair to a JWK containing only the public key.
    fn try_from(key_pair: &Ed25519KeyPair) -> Result<Self> {
        let public_key = key_pair.public_key();
        let raw_bytes = public_key.to_bytes()?;

        let okp_key = Okp {
            crv: OkpCurve::Ed25519,
            x: B64::new(raw_bytes),
            d: None,
        };

        Ok(Jwk {
            key: Key::from(okp_key),
            prm: Parameters::default(),
        })
    }
}

impl TryFrom<&Jwk> for Ed25519VerifyingKey {
    type Error = Error;

    /// Converts a JWK OKP key to an Ed25519 verifying key.
    fn try_from(jwk: &Jwk) -> Result<Self> {
        match &jwk.key {
            Key::Okp(okp_key) => match okp_key.crv {
                OkpCurve::Ed25519 => {
                    let raw_key: [u8; 32] = okp_key.x.as_ref().try_into().map_err(|_| {
                        error_msg(ErrorKind::WrongLength, "Invalid Ed25519 public key length")
                    })?;
                    Ed25519VerifyingKey::from_bytes(&raw_key)
                }
                _ => Err(Error::from(ErrorKind::UnsupportedAlgorithm)),
            },
            _ => Err(Error::from(ErrorKind::UnsupportedAlgorithm)),
        }
    }
}

impl TryFrom<&RsaKeyPair> for Jwk {
    type Error = Error;

    /// Converts an RSA key pair to a JWK containing only the public key.
    fn try_from(key_pair: &RsaKeyPair) -> Result<Self> {
        let public_key = key_pair.public_key();
        let pkcs1_der = public_key.to_pkcs1_der();

        // Parse the ASN.1 structure to extract modulus and exponent.
        // RSAPublicKey ::= SEQUENCE {
        //   modulus           INTEGER,  -- n
        //   publicExponent    INTEGER   -- e
        // }
        let asn1 = asn1::from_der(pkcs1_der)?;

        if let Some(asn1::ASN1Block::Sequence(_, blocks)) = asn1.first()
            && blocks.len() == 2
        {
            let n = if let asn1::ASN1Block::Integer(_, n_val) = &blocks[0] {
                B64::new(n_val.to_bytes_be().1)
            } else {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    "Invalid modulus in RSA public key",
                ));
            };

            let e = if let asn1::ASN1Block::Integer(_, e_val) = &blocks[1] {
                B64::new(e_val.to_bytes_be().1)
            } else {
                return Err(error_msg(
                    ErrorKind::KeyParsing,
                    "Invalid exponent in RSA public key",
                ));
            };
            let rsa_key = Rsa { n, e, prv: None };

            return Ok(Jwk {
                key: Key::from(rsa_key),
                prm: Parameters::default(),
            });
        }

        Err(error_msg(
            ErrorKind::KeyParsing,
            "Invalid ASN.1 structure for RSA public key",
        ))
    }
}

impl TryFrom<&Jwk> for RsaVerifyingKey {
    type Error = Error;

    /// Converts a JWK RSA key to an RSA verifying key.
    fn try_from(jwk: &Jwk) -> Result<Self> {
        match &jwk.key {
            Key::Rsa(rsa_key) => {
                // Reconstruct the PKCS#1 DER from the modulus and exponent.
                let n_big = asn1::BigInt::from_bytes_be(Sign::Plus, &rsa_key.n);
                let e_big = asn1::BigInt::from_bytes_be(Sign::Plus, &rsa_key.e);

                let pkcs1_der = asn1::to_der(&asn1::ASN1Block::Sequence(
                    0,
                    vec![
                        asn1::ASN1Block::Integer(0, n_big),
                        asn1::ASN1Block::Integer(0, e_big),
                    ],
                ))?;
                RsaVerifyingKey::from_pkcs1_der(&pkcs1_der)
            }
            _ => Err(Error::from(ErrorKind::UnsupportedAlgorithm)),
        }
    }
}

impl From<crate::ecdsa::Curve> for Curve {
    fn from(curve: crate::ecdsa::Curve) -> Self {
        match curve {
            crate::ecdsa::Curve::P256 => Curve::P256,
            crate::ecdsa::Curve::P384 => Curve::P384,
            crate::ecdsa::Curve::P521 => Curve::P521,
            crate::ecdsa::Curve::P256K1 => Curve::P256K1,
        }
    }
}

impl From<Curve> for crate::ecdsa::Curve {
    fn from(curve: Curve) -> Self {
        match curve {
            Curve::P256 => crate::ecdsa::Curve::P256,
            Curve::P384 => crate::ecdsa::Curve::P384,
            Curve::P521 => crate::ecdsa::Curve::P521,
            Curve::P256K1 => crate::ecdsa::Curve::P256K1,
        }
    }
}

impl From<asn1::ASN1DecodeErr> for Error {
    fn from(error: asn1::ASN1DecodeErr) -> Self {
        Error::new(ErrorKind::KeyParsing, error)
    }
}

impl From<asn1::ASN1EncodeErr> for Error {
    fn from(error: asn1::ASN1EncodeErr) -> Self {
        Error::new(ErrorKind::Serialization, error)
    }
}
