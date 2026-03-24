//! Signing algorithm identifiers.
//!
//! For JWT-based formats, SHOULD be JWS Algorithm Names from [IANA JOSE Registry].
//!
//! [IANA JOSE Registry]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A signing algorithm identifier (standard JWS or custom).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SigningAlgorithm(SigningAlgorithmInner);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SigningAlgorithmInner {
    Standard(JwsAlgorithm),
    Other(String),
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

impl SigningAlgorithm {
    #[inline]
    pub const fn standard(alg: JwsAlgorithm) -> Self {
        Self(SigningAlgorithmInner::Standard(alg))
    }

    #[inline]
    pub fn other(s: impl Into<String>) -> Self {
        Self(SigningAlgorithmInner::Other(s.into()))
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => alg.as_str(),
            SigningAlgorithmInner::Other(s) => s,
        }
    }

    pub fn as_standard(&self) -> Option<JwsAlgorithm> {
        match &self.0 {
            SigningAlgorithmInner::Standard(alg) => Some(*alg),
            SigningAlgorithmInner::Other(_) => None,
        }
    }

    pub fn is_standard(&self) -> bool {
        matches!(self.0, SigningAlgorithmInner::Standard(_))
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
        f.write_str(self.as_str())
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
            other => Self::other(other),
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
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_algorithms() {
        let alg = SigningAlgorithm::from(JwsAlgorithm::Es256);
        assert_eq!(alg.as_str(), "ES256");
        assert!(alg.is_standard());
        assert_eq!(alg.as_standard(), Some(JwsAlgorithm::Es256));
    }

    #[test]
    fn test_custom_algorithm() {
        let alg = SigningAlgorithm::other("custom-alg");
        assert_eq!(alg.as_str(), "custom-alg");
        assert!(!alg.is_standard());
        assert_eq!(alg.as_standard(), None);
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
        let alg = SigningAlgorithm::other("custom-alg");
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
