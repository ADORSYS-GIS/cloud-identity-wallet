use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{Error, IanaHashAlgorithm, Jwt, KEY_BINDING_JWT_COMPONENT};

const KEY_BINDING_JWT_TYP: &str = "kb+jwt";

/// Key Binding JWT carried by an SD-JWT presentation.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyBindingJwt<'a> {
    jwt: Jwt<'a, KeyBindingClaims>,
}

impl<'a> KeyBindingJwt<'a> {
    /// Decodes a compact Key Binding JWT.
    pub fn decode_unverified(raw: &'a str) -> Result<Self, Error> {
        let jwt = Jwt::<KeyBindingClaims>::decode_unverified(raw, KEY_BINDING_JWT_COMPONENT)?;
        validate_key_binding_profile(&jwt)?;
        Ok(Self { jwt })
    }

    /// Returns the decoded compact JWT wrapper.
    pub fn jwt(&self) -> &Jwt<'a, KeyBindingClaims> {
        &self.jwt
    }

    /// Returns the decoded Key Binding JWT claims.
    pub fn claims(&self) -> &KeyBindingClaims {
        self.jwt.claims()
    }

    /// Returns the original compact Key Binding JWT string.
    pub fn raw(&self) -> &'a str {
        self.jwt.raw()
    }
}

/// Claims required in an RFC 9901 Key Binding JWT payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBindingClaims {
    /// Issued-at time as a NumericDate.
    pub iat: i64,
    /// Intended verifier audience. RFC 9901 requires this to be a single string.
    pub aud: String,
    /// Transaction nonce used for freshness/replay protection.
    pub nonce: String,
    /// Base64url-encoded hash over the issuer-signed JWT and selected disclosures.
    pub sd_hash: String,
}

impl KeyBindingClaims {
    /// Creates new Key Binding JWT claims.
    ///
    /// # Arguments
    /// * `audience` - The verifier's client_id (aud claim)
    /// * `nonce` - The transaction nonce from the authorization request
    /// * `sd_hash` - Base64url-encoded hash of the SD-JWT presentation
    pub fn new(
        audience: impl Into<String>,
        nonce: impl Into<String>,
        sd_hash: impl Into<String>,
    ) -> Self {
        Self {
            iat: OffsetDateTime::now_utc().unix_timestamp(),
            aud: audience.into(),
            nonce: nonce.into(),
            sd_hash: sd_hash.into(),
        }
    }

    /// Creates claims with a specific issued-at timestamp.
    pub fn with_iat(mut self, iat: i64) -> Self {
        self.iat = iat;
        self
    }
}

/// Computes the `sd_hash` claim value for a Key Binding JWT.
///
/// Per RFC 9901, the `sd_hash` is a base64url-encoded hash over the
/// SD-JWT presentation (issuer JWT + disclosures + "~").
///
/// # Arguments
/// * `issuer_jwt` - The issuer-signed JWT (first part of SD-JWT)
/// * `disclosures` - The selected disclosures in order
/// * `algorithm` - The hash algorithm to use (default is SHA-256)
///
/// # Returns
/// Base64url-encoded hash value (no padding)
pub fn compute_sd_hash(
    issuer_jwt: &str,
    disclosures: &[&str],
    algorithm: IanaHashAlgorithm,
) -> String {
    let parts: Vec<&str> = std::iter::once(issuer_jwt)
        .chain(disclosures.iter().copied())
        .collect();

    let combined = parts.join("~");

    let hash_alg: cloud_wallet_crypto::digest::HashAlg = algorithm.into();
    let digest = hash_alg.hash(combined.as_bytes());

    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

fn validate_key_binding_profile(jwt: &Jwt<'_, KeyBindingClaims>) -> Result<(), Error> {
    match jwt.header().typ.as_deref() {
        Some(KEY_BINDING_JWT_TYP) => Ok(()),
        _ => Err(Error::InvalidJwtProfile {
            component: KEY_BINDING_JWT_COMPONENT,
            reason: "typ must be kb+jwt",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_binding_claims_new() {
        let claims = KeyBindingClaims::new(
            "https://verifier.example.com",
            "test-nonce-123",
            "abc123hash",
        );

        assert_eq!(claims.aud, "https://verifier.example.com");
        assert_eq!(claims.nonce, "test-nonce-123");
        assert_eq!(claims.sd_hash, "abc123hash");
        assert!(claims.iat > 0);
    }

    #[test]
    fn key_binding_claims_with_iat() {
        let claims = KeyBindingClaims::new("aud", "nonce", "hash").with_iat(1234567890);

        assert_eq!(claims.iat, 1234567890);
    }

    #[test]
    fn compute_sd_hash_without_disclosures() {
        let issuer_jwt = "eyJhbGciOiJFUzI1NiJ9.payload.signature";
        let hash = compute_sd_hash(issuer_jwt, &[], IanaHashAlgorithm::Sha256);

        assert!(!hash.is_empty());
        assert!(hash.contains(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn compute_sd_hash_with_disclosures() {
        let issuer_jwt = "eyJhbGciOiJFUzI1NiJ9.payload.signature";
        let disclosures = vec!["disclosure1", "disclosure2"];
        let hash = compute_sd_hash(issuer_jwt, &disclosures, IanaHashAlgorithm::Sha256);

        assert!(!hash.is_empty());
    }

    #[test]
    fn compute_sd_hash_deterministic() {
        let issuer_jwt = "test.jwt.token";
        let disclosures = vec!["d1", "d2"];

        let hash1 = compute_sd_hash(issuer_jwt, &disclosures, IanaHashAlgorithm::Sha256);
        let hash2 = compute_sd_hash(issuer_jwt, &disclosures, IanaHashAlgorithm::Sha256);

        assert_eq!(hash1, hash2);
    }
}
