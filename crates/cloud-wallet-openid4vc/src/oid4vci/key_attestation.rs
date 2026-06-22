//! Key Attestation for OID4VCI per Appendix D and HAIP §4.5.1.
//!
//! Key attestations are JWTs signed by a secure key management backend that attest
//! to properties of keys used for holder binding in credential requests.
//!
//! Reference: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-attestation

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cloud_wallet_crypto::jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use time::OffsetDateTime;

use crate::errors::{Error, ErrorKind};

pub const KEY_ATTESTATION_JWT_TYP: &str = "key-attestation+jwt";

/// Attack potential resistance values per ISO 18045 (Appendix D.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPotential {
    #[serde(rename = "iso_18045_high")]
    High,
    #[serde(rename = "iso_18045_moderate")]
    Moderate,
    #[serde(rename = "iso_18045_enhanced-basic")]
    EnhancedBasic,
    #[serde(rename = "iso_18045_basic")]
    Basic,
}

impl AttackPotential {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "iso_18045_high",
            Self::Moderate => "iso_18045_moderate",
            Self::EnhancedBasic => "iso_18045_enhanced-basic",
            Self::Basic => "iso_18045_basic",
        }
    }
}

/// Claims in a Key Attestation JWT per OID4VCI Appendix D.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestationClaims {
    /// Issuer of the key attestation (the secure key management backend).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Time at which the key attestation was issued (REQUIRED).
    pub iat: i64,

    /// Expiration time for the attestation and key(s).
    /// MUST be present if used with JWT proof type.
    pub exp: Option<i64>,

    /// Non-empty array of attested keys using JWK syntax (REQUIRED).
    pub attested_keys: Vec<Jwk>,

    /// Non-empty array asserting attack potential resistance of key storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<Vec<String>>,

    /// Non-empty array asserting attack potential resistance of user authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<Vec<String>>,

    /// URL linking to certification of the key storage component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certification: Option<String>,

    /// Server-provided nonce to prove attestation was freshly generated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// JSON Object for supported revocation check mechanisms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

impl KeyAttestationClaims {
    /// Creates a new KeyAttestationClaims with the minimal required fields.
    pub fn new(attested_keys: Vec<Jwk>) -> Self {
        Self {
            iss: None,
            iat: OffsetDateTime::now_utc().unix_timestamp(),
            exp: None,
            attested_keys,
            key_storage: None,
            user_authentication: None,
            certification: None,
            nonce: None,
            status: None,
        }
    }

    /// Sets the issuer of the key attestation.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    /// Sets the expiration time.
    pub fn with_expiration(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Sets the key storage security level.
    pub fn with_key_storage(mut self, levels: Vec<String>) -> Self {
        self.key_storage = Some(levels);
        self
    }

    /// Sets the user authentication security level.
    pub fn with_user_authentication(mut self, levels: Vec<String>) -> Self {
        self.user_authentication = Some(levels);
        self
    }

    /// Sets the certification URL.
    pub fn with_certification(mut self, url: impl Into<String>) -> Self {
        self.certification = Some(url.into());
        self
    }

    /// Sets the nonce for freshness.
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Validates that all required fields are present and valid.
    pub fn validate(&self) -> Result<(), KeyAttestationError> {
        if self.attested_keys.is_empty() {
            return Err(KeyAttestationError::MissingAttestedKeys);
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();

        if self.iat > now {
            return Err(KeyAttestationError::IssuedInFuture);
        }

        if let Some(exp) = self.exp
            && exp < now
        {
            return Err(KeyAttestationError::Expired);
        }

        Ok(())
    }
}

/// JOSE Header for Key Attestation JWTs.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAttestationHeader {
    /// Digital signature algorithm (REQUIRED, MUST NOT be `none` or symmetric).
    pub alg: String,

    /// JWT type (REQUIRED, MUST be "key-attestation+jwt").
    pub typ: String,

    /// Certificate chain for the public key (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// Key ID (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// OpenID Federation Trust Chain (OPTIONAL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<Vec<String>>,
}

impl KeyAttestationHeader {
    /// Creates a new header with the specified algorithm.
    pub fn new(algorithm: impl Into<String>) -> Self {
        Self {
            alg: algorithm.into(),
            typ: KEY_ATTESTATION_JWT_TYP.to_string(),
            x5c: None,
            kid: None,
            trust_chain: None,
        }
    }

    /// Adds a certificate chain.
    pub fn with_certificate_chain(mut self, certs: Vec<String>) -> Self {
        self.x5c = Some(certs);
        self
    }

    /// Adds a key ID.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Adds a trust chain.
    pub fn with_trust_chain(mut self, chain: Vec<String>) -> Self {
        self.trust_chain = Some(chain);
        self
    }
}

/// A decoded and validated Key Attestation JWT.
#[derive(Debug, Clone)]
pub struct KeyAttestationJwt {
    header: KeyAttestationHeader,
    claims: KeyAttestationClaims,
    raw: String,
}

impl KeyAttestationJwt {
    /// The expected `typ` header value for Key Attestation JWTs.
    pub const EXPECTED_TYP: &'static str = KEY_ATTESTATION_JWT_TYP;

    /// Decodes a Key Attestation JWT without signature verification.
    ///
    /// This performs structural and temporal validation but does NOT verify
    /// the signature. The caller is responsible for verifying the signature
    /// against a trusted attestation issuer's key.
    pub fn decode_unverified(jwt: &str) -> Result<Self, KeyAttestationError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(KeyAttestationError::InvalidFormat(
                "JWT must have 3 parts".to_string(),
            ));
        }

        let header: KeyAttestationHeader = base64_decode_json(parts[0]).map_err(|e| {
            KeyAttestationError::InvalidFormat(format!("failed to decode header: {e}"))
        })?;

        if header.typ != Self::EXPECTED_TYP {
            return Err(KeyAttestationError::InvalidTyp {
                expected: Self::EXPECTED_TYP.to_string(),
                actual: header.typ,
            });
        }

        let claims: KeyAttestationClaims = base64_decode_json(parts[1]).map_err(|e| {
            KeyAttestationError::InvalidFormat(format!("failed to decode claims: {e}"))
        })?;

        claims.validate()?;

        Ok(Self {
            header,
            claims,
            raw: jwt.to_string(),
        })
    }

    /// Returns the header.
    pub fn header(&self) -> &KeyAttestationHeader {
        &self.header
    }

    /// Returns the claims.
    pub fn claims(&self) -> &KeyAttestationClaims {
        &self.claims
    }

    /// Returns the raw JWT string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the attested keys.
    pub fn attested_keys(&self) -> &[Jwk] {
        &self.claims.attested_keys
    }

    /// Returns the key storage security levels.
    pub fn key_storage(&self) -> Option<&[String]> {
        self.claims.key_storage.as_deref()
    }

    /// Returns the user authentication security levels.
    pub fn user_authentication(&self) -> Option<&[String]> {
        self.claims.user_authentication.as_deref()
    }

    /// Validates that the attestation meets the required key storage levels.
    pub fn meets_key_storage_requirements(&self, required: &[String]) -> bool {
        match &self.claims.key_storage {
            Some(provided) => required.iter().all(|r| provided.contains(r)),
            None => required.is_empty(),
        }
    }

    /// Validates that the attestation meets the required user authentication levels.
    pub fn meets_user_authentication_requirements(&self, required: &[String]) -> bool {
        match &self.claims.user_authentication {
            Some(provided) => required.iter().all(|r| provided.contains(r)),
            None => required.is_empty(),
        }
    }
}

/// Requirements for key attestations from issuer metadata.
#[derive(Debug, Clone, Default)]
pub struct KeyAttestationRequirements {
    /// Required key storage security levels.
    pub key_storage: Option<Vec<String>>,

    /// Required user authentication security levels.
    pub user_authentication: Option<Vec<String>>,
}

impl KeyAttestationRequirements {
    /// Creates requirements from issuer metadata.
    pub fn from_metadata(
        key_attestations_required: Option<&crate::oid4vci::metadata::KeyAttestationsRequired>,
    ) -> Self {
        match key_attestations_required {
            Some(req) => Self {
                key_storage: req.key_storage.clone(),
                user_authentication: req.user_authentication.clone(),
            },
            None => Self::default(),
        }
    }

    /// Returns true if any attestation requirements are specified.
    pub fn is_required(&self) -> bool {
        self.key_storage.is_some() || self.user_authentication.is_some()
    }

    /// Validates that the attestation meets the requirements.
    pub fn validate(&self, attestation: &KeyAttestationJwt) -> Result<(), KeyAttestationError> {
        if let Some(ref required) = self.key_storage
            && !attestation.meets_key_storage_requirements(required)
        {
            return Err(KeyAttestationError::InsufficientKeyStorage {
                required: required.clone(),
                provided: attestation.claims.key_storage.clone().unwrap_or_default(),
            });
        }

        if let Some(ref required) = self.user_authentication
            && !attestation.meets_user_authentication_requirements(required)
        {
            return Err(KeyAttestationError::InsufficientUserAuthentication {
                required: required.clone(),
                provided: attestation.claims.user_authentication.clone().unwrap_or_default(),
            });
        }

        Ok(())
    }
}

/// Builder for creating Key Attestation JWTs.
///
/// This is used by the attestation issuer (secure key management backend)
/// to create attestations. The client wallet receives pre-signed attestations.
#[derive(Debug)]
pub struct KeyAttestationBuilder {
    claims: KeyAttestationClaims,
    header: KeyAttestationHeader,
}

impl KeyAttestationBuilder {
    /// Creates a new builder with the minimum required claims.
    pub fn new(attested_keys: Vec<Jwk>, algorithm: impl Into<String>) -> Self {
        Self {
            claims: KeyAttestationClaims::new(attested_keys),
            header: KeyAttestationHeader::new(algorithm),
        }
    }

    /// Sets the issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.claims.iss = Some(issuer.into());
        self
    }

    /// Sets the expiration time.
    pub fn expiration(mut self, exp: i64) -> Self {
        self.claims.exp = Some(exp);
        self
    }

    /// Sets the key storage security levels.
    pub fn key_storage(mut self, levels: Vec<String>) -> Self {
        self.claims.key_storage = Some(levels);
        self
    }

    /// Sets the user authentication security levels.
    pub fn user_authentication(mut self, levels: Vec<String>) -> Self {
        self.claims.user_authentication = Some(levels);
        self
    }

    /// Sets the certification URL.
    pub fn certification(mut self, url: impl Into<String>) -> Self {
        self.claims.certification = Some(url.into());
        self
    }

    /// Sets the nonce for freshness.
    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.claims.nonce = Some(nonce.into());
        self
    }

    /// Sets the key ID in the header.
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.header.kid = Some(kid.into());
        self
    }

    /// Sets the certificate chain in the header.
    pub fn certificate_chain(mut self, certs: Vec<String>) -> Self {
        self.header.x5c = Some(certs);
        self
    }

    /// Sets the trust chain in the header.
    pub fn trust_chain(mut self, chain: Vec<String>) -> Self {
        self.header.trust_chain = Some(chain);
        self
    }

    /// Encodes the attestation to a JWT string without signing.
    ///
    /// The resulting JWT should be signed by a secure key management backend.
    /// This method is provided for testing and for integrations where the
    /// signing is performed externally.
    pub fn encode_un_signed(&self) -> Result<String, KeyAttestationError> {
        self.claims.validate()?;

        let header_b64 = base64_encode_json(&self.header)?;
        let claims_b64 = base64_encode_json(&self.claims)?;

        let placeholder_sig = URL_SAFE_NO_PAD.encode(b"");
        Ok(format!("{}.{}.{}", header_b64, claims_b64, placeholder_sig))
    }

    /// Returns the claims for external signing.
    pub fn claims(&self) -> &KeyAttestationClaims {
        &self.claims
    }

    /// Returns the header for external signing.
    pub fn header(&self) -> &KeyAttestationHeader {
        &self.header
    }
}

/// Encodes a key attestation for embedding in a proof JWT header.
///
/// The attestation is included as the `attestation` field in the proof JWT header
/// per OID4VCI Appendix D.
pub fn encode_attestation_for_proof_header(attestation_jwt: &str) -> String {
    attestation_jwt.to_string()
}

/// Decodes and validates multiple attestations batched together.
///
/// For batch issuance, multiple keys can be attested in a single attestation.
/// This validates that all required keys are present in the attestation.
pub fn validate_batch_attestation(
    attestation_jwt: &str,
    required_keys: &[Jwk],
) -> Result<KeyAttestationJwt, KeyAttestationError> {
    let attestation = KeyAttestationJwt::decode_unverified(attestation_jwt)?;

    for required_key in required_keys {
        let found = attestation
            .attested_keys()
            .iter()
            .any(|k| keys_match(k, required_key));
        if !found {
            return Err(KeyAttestationError::MissingAttestedKey);
        }
    }

    Ok(attestation)
}

/// Checks if two JWKs represent the same key (by public key material).
fn keys_match(a: &Jwk, b: &Jwk) -> bool {
    use cloud_wallet_crypto::jwk::Key;
    match (&a.key, &b.key) {
        (Key::Ec(ec_a), Key::Ec(ec_b)) => {
            ec_a.crv == ec_b.crv && ec_a.x == ec_b.x && ec_a.y == ec_b.y
        }
        (Key::Rsa(rsa_a), Key::Rsa(rsa_b)) => rsa_a.n == rsa_b.n && rsa_a.e == rsa_b.e,
        (Key::Okp(okp_a), Key::Okp(okp_b)) => okp_a.crv == okp_b.crv && okp_a.x == okp_b.x,
        (Key::Oct(oct_a), Key::Oct(oct_b)) => oct_a.k.expose() == oct_b.k.expose(),
        _ => false,
    }
}

fn base64_decode_json<T: for<'de> Deserialize<'de>>(b64: &str) -> Result<T, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("base64 decode error: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON decode error: {e}"))
}

fn base64_encode_json<T: Serialize>(value: &T) -> Result<String, KeyAttestationError> {
    let serialized = serde_json::to_vec(value)
        .map_err(|e| KeyAttestationError::EncodingFailed(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(&serialized))
}

/// Errors related to Key Attestations.
#[derive(Debug, thiserror::Error)]
pub enum KeyAttestationError {
    #[error("invalid key attestation format: {0}")]
    InvalidFormat(String),

    #[error("invalid typ header: expected {expected}, got {actual}")]
    InvalidTyp { expected: String, actual: String },

    #[error("missing attested_keys")]
    MissingAttestedKeys,

    #[error("missing attested key")]
    MissingAttestedKey,

    #[error("key attestation expired")]
    Expired,

    #[error("key attestation issued in the future")]
    IssuedInFuture,

    #[error("insufficient key storage: required {required:?}, provided {provided:?}")]
    InsufficientKeyStorage {
        required: Vec<String>,
        provided: Vec<String>,
    },

    #[error("insufficient user authentication: required {required:?}, provided {provided:?}")]
    InsufficientUserAuthentication {
        required: Vec<String>,
        provided: Vec<String>,
    },

    #[error("encoding failed: {0}")]
    EncodingFailed(String),
}

impl From<KeyAttestationError> for Error {
    fn from(err: KeyAttestationError) -> Self {
        Error::message(ErrorKind::InvalidCredentialRequest, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ec_jwk() -> Jwk {
        let keypair =
            cloud_wallet_crypto::ecdsa::KeyPair::generate(cloud_wallet_crypto::ecdsa::Curve::P256)
                .expect("failed to generate key");
        Jwk::try_from(&keypair).expect("failed to convert to JWK")
    }

    #[test]
    fn test_key_attestation_claims_new() {
        let jwk = sample_ec_jwk();
        let claims = KeyAttestationClaims::new(vec![jwk.clone()]);

        assert!(claims.iss.is_none());
        assert!(claims.exp.is_none());
        assert!(claims.key_storage.is_none());
        assert!(claims.user_authentication.is_none());
        assert_eq!(claims.attested_keys.len(), 1);
    }

    #[test]
    fn test_key_attestation_claims_builder() {
        let jwk = sample_ec_jwk();
        let claims = KeyAttestationClaims::new(vec![jwk])
            .with_issuer("https://attestation.example.com")
            .with_expiration(1234567890)
            .with_key_storage(vec!["iso_18045_moderate".to_string()])
            .with_user_authentication(vec!["iso_18045_moderate".to_string()])
            .with_nonce("test-nonce".to_string());

        assert_eq!(
            claims.iss,
            Some("https://attestation.example.com".to_string())
        );
        assert_eq!(claims.exp, Some(1234567890));
        assert!(claims.key_storage.is_some());
        assert!(claims.user_authentication.is_some());
        assert_eq!(claims.nonce, Some("test-nonce".to_string()));
    }

    #[test]
    fn test_key_attestation_claims_validate_empty_keys() {
        let claims = KeyAttestationClaims::new(vec![]);
        let result = claims.validate();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(KeyAttestationError::MissingAttestedKeys)
        ));
    }

    #[test]
    fn test_attack_potential_serialization() {
        let high = AttackPotential::High;
        assert_eq!(high.as_str(), "iso_18045_high");

        let moderate = AttackPotential::Moderate;
        assert_eq!(moderate.as_str(), "iso_18045_moderate");
    }

    #[test]
    fn test_key_attestation_header() {
        let header = KeyAttestationHeader::new("ES256");
        assert_eq!(header.typ, "key-attestation+jwt");
        assert_eq!(header.alg, "ES256");

        let header_with_kid = header.with_kid("key-1");
        assert_eq!(header_with_kid.kid, Some("key-1".to_string()));
    }

    #[test]
    fn test_key_attestation_requirements() {
        let no_requirements = KeyAttestationRequirements::default();
        assert!(!no_requirements.is_required());

        let with_requirements = KeyAttestationRequirements {
            key_storage: Some(vec!["iso_18045_moderate".to_string()]),
            user_authentication: None,
        };
        assert!(with_requirements.is_required());
    }

    #[test]
    fn test_attestation_meets_requirements() {
        let jwk = sample_ec_jwk();
        let claims = KeyAttestationClaims::new(vec![jwk])
            .with_key_storage(vec!["iso_18045_moderate".to_string()])
            .with_user_authentication(vec!["iso_18045_moderate".to_string()]);

        let exp = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let claims = claims.with_expiration(exp);

        let attestation_jwt =
            KeyAttestationJwt::decode_unverified(&create_test_jwt(&claims)).unwrap();

        assert!(
            attestation_jwt.meets_key_storage_requirements(&["iso_18045_moderate".to_string()])
        );
        assert!(!attestation_jwt.meets_key_storage_requirements(&["iso_18045_high".to_string()]));
        assert!(
            attestation_jwt
                .meets_user_authentication_requirements(&["iso_18045_moderate".to_string()])
        );
    }

    #[test]
    fn test_validate_batch_attestation() {
        let key1 = sample_ec_jwk();
        let key2 = sample_ec_jwk();

        let claims = KeyAttestationClaims::new(vec![key1.clone(), key2.clone()]);
        let jwt = create_test_jwt(&claims);

        let result = validate_batch_attestation(&jwt, &[key1.clone(), key2]);
        assert!(result.is_ok());

        let key3 = sample_ec_jwk();
        let result = validate_batch_attestation(&jwt, &[key1, key3]);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(KeyAttestationError::MissingAttestedKey)
        ));
    }

    #[test]
    fn test_missing_attestation_rejection() {
        let requirements = KeyAttestationRequirements {
            key_storage: Some(vec!["iso_18045_moderate".to_string()]),
            user_authentication: None,
        };

        assert!(requirements.is_required());

        let attestation = KeyAttestationJwt::decode_unverified(&create_test_jwt(
            &KeyAttestationClaims::new(vec![sample_ec_jwk()]),
        ))
        .unwrap();

        // Attestation meets requirements but missing key_storage level
        let other_requirements = KeyAttestationRequirements {
            key_storage: Some(vec!["iso_18045_high".to_string()]),
            user_authentication: None,
        };
        let result = other_requirements.validate(&attestation);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(KeyAttestationError::InsufficientKeyStorage { .. })
        ));
    }

    #[test]
    fn test_no_requirements_attestation() {
        let requirements = KeyAttestationRequirements::default();
        assert!(!requirements.is_required());

        let attestation = KeyAttestationJwt::decode_unverified(&create_test_jwt(
            &KeyAttestationClaims::new(vec![sample_ec_jwk()]),
        ))
        .unwrap();

        // No requirements, any attestation should pass
        let result = requirements.validate(&attestation);
        assert!(result.is_ok());
    }

    fn create_test_jwt(claims: &KeyAttestationClaims) -> String {
        let header = KeyAttestationHeader::new("ES256");
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        format!("{}.{}.signature", header_b64, claims_b64)
    }
}
