//! Signing algorithm identifiers.
//!
//! For JWT-based formats, SHOULD be JWS Algorithm Names from [IANA JOSE Registry].
//! For mso_mdoc format, MUST be numeric COSE algorithm identifiers from [IANA COSE Registry].
//!
//! [IANA JOSE Registry]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
//! [IANA COSE Registry]: https://www.iana.org/assignments/cose/cose.xhtml#algorithms

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A signing algorithm identifier.
///
/// Can be either a string (JWS algorithm name for JWT-based formats) or an integer
/// (COSE algorithm identifier for mso_mdoc format).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SigningAlgorithm(SigningAlgorithmInner);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SigningAlgorithmInner {
    /// Standard JWS algorithm (string identifier).
    Standard(JwsAlgorithm),
    /// Standard COSE algorithm (integer identifier).
    Cose(CoseAlgorithm),
    /// Custom string identifier.
    OtherString(String),
    /// Custom integer identifier.
    OtherInt(i64),
}

/// Standard JWS algorithm identifiers from [RFC 7518 Section 3.1].
///
/// [RFC 7518 Section 3.1]: https://www.rfc-editor.org/rfc/rfc7518#section-3.1
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JwsAlgorithm {
    EdDsa,
    Es256,
    Es256K,
    Es384,
    Es512,
    Hs256,
    Hs384,
    Hs512,
    Ps256,
    Ps384,
    Ps512,
    Rs256,
    Rs384,
    Rs512,
}

/// Standard COSE algorithm identifiers from [IANA COSE Algorithms Registry].
///
/// These are numeric identifiers used in COSE structures for mso_mdoc credentials.
///
/// [IANA COSE Algorithms Registry]: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseAlgorithm {
    /// ECDSA with SHA-256 (alg: -7)
    EcdsaSha256,
    /// ECDSA with SHA-384 (alg: -35)
    EcdsaSha384,
    /// ECDSA with SHA-512 (alg: -36)
    EcdsaSha512,
    /// ECDSA with P-256 and SHA-256, fully specified (alg: -9)
    EcdsaP256Sha256,
    /// EdDSA with Ed25519 (alg: -8)
    EdDsa,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (alg: -257)
    RsassaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384 (alg: -258)
    RsassaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512 (alg: -259)
    RsassaPkcs1Sha512,
    /// RSASSA-PSS with SHA-256 (alg: -37)
    RsassaPssSha256,
    /// RSASSA-PSS with SHA-384 (alg: -38)
    RsassaPssSha384,
    /// RSASSA-PSS with SHA-512 (alg: -39)
    RsassaPssSha512,
}

impl CoseAlgorithm {
    /// Returns the COSE algorithm identifier as an integer.
    pub const fn as_int(self) -> i64 {
        match self {
            Self::EcdsaSha256 => -7,
            Self::EcdsaSha384 => -35,
            Self::EcdsaSha512 => -36,
            Self::EcdsaP256Sha256 => -9,
            Self::EdDsa => -8,
            Self::RsassaPkcs1Sha256 => -257,
            Self::RsassaPkcs1Sha384 => -258,
            Self::RsassaPkcs1Sha512 => -259,
            Self::RsassaPssSha256 => -37,
            Self::RsassaPssSha384 => -38,
            Self::RsassaPssSha512 => -39,
        }
    }

    /// Attempts to convert an integer to a known COSE algorithm.
    pub fn from_int(n: i64) -> Option<Self> {
        match n {
            -7 => Some(Self::EcdsaSha256),
            -35 => Some(Self::EcdsaSha384),
            -36 => Some(Self::EcdsaSha512),
            -9 => Some(Self::EcdsaP256Sha256),
            -8 => Some(Self::EdDsa),
            -257 => Some(Self::RsassaPkcs1Sha256),
            -258 => Some(Self::RsassaPkcs1Sha384),
            -259 => Some(Self::RsassaPkcs1Sha512),
            -37 => Some(Self::RsassaPssSha256),
            -38 => Some(Self::RsassaPssSha384),
            -39 => Some(Self::RsassaPssSha512),
            _ => None,
        }
    }
}

impl fmt::Display for CoseAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_int())
    }
}

impl SigningAlgorithm {
    /// Creates a signing algorithm from a standard JWS algorithm name.
    #[inline]
    pub const fn standard(alg: JwsAlgorithm) -> Self {
        Self(SigningAlgorithmInner::Standard(alg))
    }

    /// Creates a signing algorithm from a standard COSE algorithm identifier.
    #[inline]
    pub const fn cose(alg: CoseAlgorithm) -> Self {
        Self(SigningAlgorithmInner::Cose(alg))
    }

    /// Creates a signing algorithm from a custom string identifier.
    #[inline]
    pub fn other_string(s: impl Into<String>) -> Self {
        Self(SigningAlgorithmInner::OtherString(s.into()))
    }

    /// Creates a signing algorithm from a custom integer identifier.
    #[inline]
    pub const fn other_int(n: i64) -> Self {
        Self(SigningAlgorithmInner::OtherInt(n))
    }

    /// Returns the algorithm as a string, if it is a string-based identifier.
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => Some(alg.as_str()),
            SigningAlgorithmInner::Cose(_) => None,
            SigningAlgorithmInner::OtherString(s) => Some(s),
            SigningAlgorithmInner::OtherInt(_) => None,
        }
    }

    /// Returns the algorithm as an integer, if it is an integer-based identifier.
    pub fn as_int(&self) -> Option<i64> {
        match &self.0 {
            SigningAlgorithmInner::Standard(_) => None,
            SigningAlgorithmInner::Cose(alg) => Some(alg.as_int()),
            SigningAlgorithmInner::OtherString(_) => None,
            SigningAlgorithmInner::OtherInt(n) => Some(*n),
        }
    }

    /// Returns the standard JWS algorithm, if this is one.
    pub fn as_standard(&self) -> Option<JwsAlgorithm> {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => Some(*alg),
            _ => None,
        }
    }

    /// Returns the standard COSE algorithm, if this is one.
    pub fn as_cose(&self) -> Option<CoseAlgorithm> {
        match &self.0 {
            SigningAlgorithmInner::Cose(alg) => Some(*alg),
            _ => None,
        }
    }

    /// Returns true if this is a standard JWS algorithm.
    pub fn is_standard(&self) -> bool {
        matches!(self.0, SigningAlgorithmInner::Standard(_))
    }

    /// Returns true if this is a standard COSE algorithm.
    pub fn is_cose(&self) -> bool {
        matches!(self.0, SigningAlgorithmInner::Cose(_))
    }

    /// Returns true if this is a string-based identifier.
    pub fn is_string(&self) -> bool {
        matches!(
            self.0,
            SigningAlgorithmInner::Standard(_) | SigningAlgorithmInner::OtherString(_)
        )
    }

    /// Returns true if this is an integer-based identifier.
    pub fn is_int(&self) -> bool {
        matches!(
            self.0,
            SigningAlgorithmInner::Cose(_) | SigningAlgorithmInner::OtherInt(_)
        )
    }
}

impl JwsAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es256K => "ES256K",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => f.write_str(alg.as_str()),
            SigningAlgorithmInner::Cose(alg) => write!(f, "{}", alg.as_int()),
            SigningAlgorithmInner::OtherString(s) => f.write_str(s),
            SigningAlgorithmInner::OtherInt(n) => write!(f, "{}", n),
        }
    }
}

impl fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<JwsAlgorithm> for SigningAlgorithm {
    #[inline]
    fn from(alg: JwsAlgorithm) -> Self {
        Self::standard(alg)
    }
}

impl From<&str> for SigningAlgorithm {
    fn from(s: &str) -> Self {
        match s {
            "EdDSA" => Self::standard(JwsAlgorithm::EdDsa),
            "ES256" => Self::standard(JwsAlgorithm::Es256),
            "ES256K" => Self::standard(JwsAlgorithm::Es256K),
            "ES384" => Self::standard(JwsAlgorithm::Es384),
            "ES512" => Self::standard(JwsAlgorithm::Es512),
            "HS256" => Self::standard(JwsAlgorithm::Hs256),
            "HS384" => Self::standard(JwsAlgorithm::Hs384),
            "HS512" => Self::standard(JwsAlgorithm::Hs512),
            "PS256" => Self::standard(JwsAlgorithm::Ps256),
            "PS384" => Self::standard(JwsAlgorithm::Ps384),
            "PS512" => Self::standard(JwsAlgorithm::Ps512),
            "RS256" => Self::standard(JwsAlgorithm::Rs256),
            "RS384" => Self::standard(JwsAlgorithm::Rs384),
            "RS512" => Self::standard(JwsAlgorithm::Rs512),
            other => Self::other_string(other),
        }
    }
}

impl From<i64> for SigningAlgorithm {
    fn from(n: i64) -> Self {
        match CoseAlgorithm::from_int(n) {
            Some(alg) => Self::cose(alg),
            None => Self::other_int(n),
        }
    }
}

impl From<String> for SigningAlgorithm {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl Serialize for SigningAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => serializer.serialize_str(alg.as_str()),
            SigningAlgorithmInner::Cose(alg) => serializer.serialize_i64(alg.as_int()),
            SigningAlgorithmInner::OtherString(s) => serializer.serialize_str(s),
            SigningAlgorithmInner::OtherInt(n) => serializer.serialize_i64(*n),
        }
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, Visitor};

        struct SigningAlgorithmVisitor;

        impl<'de> Visitor<'de> for SigningAlgorithmVisitor {
            type Value = SigningAlgorithm;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string or integer algorithm identifier")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(SigningAlgorithm::from(v))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(SigningAlgorithm::from(v.as_str()))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(SigningAlgorithm::from(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v <= i64::MAX as u64 {
                    Ok(SigningAlgorithm::from(v as i64))
                } else {
                    Err(E::custom(format!(
                        "algorithm identifier {} is too large",
                        v
                    )))
                }
            }
        }

        deserializer.deserialize_any(SigningAlgorithmVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_algorithms() {
        let alg = SigningAlgorithm::from(JwsAlgorithm::Es256);
        assert_eq!(alg.as_str(), Some("ES256"));
        assert!(alg.is_standard());
        assert_eq!(alg.as_standard(), Some(JwsAlgorithm::Es256));
    }

    #[test]
    fn test_custom_string_algorithm() {
        let alg = SigningAlgorithm::other_string("custom-alg");
        assert_eq!(alg.as_str(), Some("custom-alg"));
        assert!(!alg.is_standard());
        assert!(!alg.is_cose());
        assert!(alg.is_string());
        assert_eq!(alg.as_standard(), None);
        assert_eq!(alg.as_int(), None);
    }

    #[test]
    fn test_custom_int_algorithm() {
        let alg = SigningAlgorithm::other_int(-999);
        assert_eq!(alg.as_int(), Some(-999));
        assert!(!alg.is_standard());
        assert!(!alg.is_cose());
        assert!(alg.is_int());
        assert_eq!(alg.as_standard(), None);
        assert_eq!(alg.as_str(), None);
    }

    #[test]
    fn test_cose_algorithm() {
        let alg = SigningAlgorithm::cose(CoseAlgorithm::EcdsaSha256);
        assert_eq!(alg.as_int(), Some(-7));
        assert!(alg.is_cose());
        assert!(!alg.is_standard());
        assert!(alg.is_int());
        assert_eq!(alg.as_cose(), Some(CoseAlgorithm::EcdsaSha256));
    }

    #[test]
    fn test_serde_cose() {
        let alg = SigningAlgorithm::cose(CoseAlgorithm::EcdsaSha256);
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "-7");

        let parsed: SigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn test_serde_int() {
        let alg = SigningAlgorithm::other_int(-42);
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "-42");

        let parsed: SigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn test_from_int() {
        let alg = SigningAlgorithm::from(-7);
        assert!(alg.is_cose());
        assert_eq!(alg.as_cose(), Some(CoseAlgorithm::EcdsaSha256));

        let custom = SigningAlgorithm::from(-999);
        assert!(!custom.is_cose());
        assert_eq!(custom.as_int(), Some(-999));
    }

    #[test]
    fn test_serde_standard() {
        let alg = SigningAlgorithm::from(JwsAlgorithm::Es256);
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"ES256\"");

        let parsed: SigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn test_serde_custom() {
        let alg = SigningAlgorithm::other_string("custom-alg");
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"custom-alg\"");

        let parsed: SigningAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, alg);
    }

    #[test]
    fn test_case_sensitive() {
        // Algorithm identifiers are case-sensitive
        let lower = SigningAlgorithm::from("es256");
        let upper = SigningAlgorithm::from("ES256");

        assert_ne!(lower, upper);
        assert!(upper.is_standard());
        assert!(!lower.is_standard());
    }
}
