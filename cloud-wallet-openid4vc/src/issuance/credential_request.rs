//! Credential Request models for OpenID4VCI §8.2.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::errors::{Error, ErrorKind};

fn invalid_credential_request(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidCredentialRequest, message.into())
}

fn deserialize_non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    if value.is_empty() {
        return Err(de::Error::custom("value must not be empty"));
    }

    Ok(value)
}

fn deserialize_non_empty_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;

    if values.is_empty() {
        return Err(de::Error::custom(
            "proof arrays must contain at least one entry",
        ));
    }

    if values.iter().any(String::is_empty) {
        return Err(de::Error::custom(
            "proof arrays must not contain empty entries",
        ));
    }

    Ok(values)
}

fn deserialize_non_empty_object_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;

    if values.is_empty() {
        return Err(de::Error::custom(
            "proof arrays must contain at least one entry",
        ));
    }

    if values.iter().any(|value| !value.is_object()) {
        return Err(de::Error::custom("di_vp proofs must contain JSON objects"));
    }

    Ok(values)
}

fn deserialize_single_attestation<'de, D>(deserializer: D) -> Result<[String; 1], D::Error>
where
    D: Deserializer<'de>,
{
    let attestation = <[String; 1]>::deserialize(deserializer)?;

    if attestation[0].is_empty() {
        return Err(de::Error::custom("attestation proof must not be empty"));
    }

    Ok(attestation)
}

/// The `proofs` object defined by OpenID4VCI §8.2.1.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proofs {
    #[serde(flatten)]
    inner: ProofsInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum ProofsInner {
    Jwt(JwtProofs),
    DiVp(DiVpProofs),
    Attestation(AttestationProofs),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtProofs {
    #[serde(deserialize_with = "deserialize_non_empty_string_vec")]
    jwt: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiVpProofs {
    #[serde(deserialize_with = "deserialize_non_empty_object_vec")]
    di_vp: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationProofs {
    #[serde(deserialize_with = "deserialize_single_attestation")]
    attestation: [String; 1],
}

impl Proofs {
    /// Creates a `proofs.jwt` array.
    pub fn jwt<I, S>(proofs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            inner: ProofsInner::Jwt(JwtProofs {
                jwt: proofs.into_iter().map(Into::into).collect(),
            }),
        }
    }

    /// Creates a `proofs.di_vp` array.
    pub fn di_vp<I>(proofs: I) -> Self
    where
        I: IntoIterator<Item = serde_json::Value>,
    {
        Self {
            inner: ProofsInner::DiVp(DiVpProofs {
                di_vp: proofs.into_iter().collect(),
            }),
        }
    }

    /// Creates a single-entry `proofs.attestation` array.
    pub fn attestation(attestation: impl Into<String>) -> Self {
        Self {
            inner: ProofsInner::Attestation(AttestationProofs {
                attestation: [attestation.into()],
            }),
        }
    }

    /// Returns the total number of proof entries for the active proof type.
    pub fn len(&self) -> usize {
        match &self.inner {
            ProofsInner::Jwt(proofs) => proofs.jwt.len(),
            ProofsInner::DiVp(proofs) => proofs.di_vp.len(),
            ProofsInner::Attestation(_) => 1,
        }
    }

    /// Returns true when the active proof list has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the JWT proof entries when the active proof type is `jwt`.
    pub fn jwt_proofs(&self) -> Option<&[String]> {
        match &self.inner {
            ProofsInner::Jwt(proofs) => Some(&proofs.jwt),
            ProofsInner::DiVp(_) | ProofsInner::Attestation(_) => None,
        }
    }

    /// Returns the Data Integrity proof entries when the active proof type is `di_vp`.
    pub fn di_vp_proofs(&self) -> Option<&[serde_json::Value]> {
        match &self.inner {
            ProofsInner::DiVp(proofs) => Some(&proofs.di_vp),
            ProofsInner::Jwt(_) | ProofsInner::Attestation(_) => None,
        }
    }

    /// Returns the attestation proof when the active proof type is `attestation`.
    pub fn attestation_proof(&self) -> Option<&str> {
        match &self.inner {
            ProofsInner::Attestation(proofs) => Some(&proofs.attestation[0]),
            ProofsInner::Jwt(_) | ProofsInner::DiVp(_) => None,
        }
    }

    fn validation_error(&self) -> Option<&'static str> {
        match &self.inner {
            ProofsInner::Jwt(proofs) if proofs.jwt.is_empty() => {
                Some("jwt proofs must contain at least one entry")
            }
            ProofsInner::Jwt(proofs) if proofs.jwt.iter().any(String::is_empty) => {
                Some("jwt proofs must not contain empty entries")
            }
            ProofsInner::DiVp(proofs) if proofs.di_vp.is_empty() => {
                Some("di_vp proofs must contain at least one entry")
            }
            ProofsInner::DiVp(proofs) if proofs.di_vp.iter().any(|value| !value.is_object()) => {
                Some("di_vp proofs must contain JSON objects")
            }
            ProofsInner::Attestation(proofs) if proofs.attestation[0].is_empty() => {
                Some("attestation proof must not be empty")
            }
            _ => None,
        }
    }

    /// Validates that the populated proof-type entry is spec-compliant.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(message) = self.validation_error() {
            return Err(invalid_credential_request(message));
        }

        Ok(())
    }
}

/// Response-encryption parameters supplied by the Wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResponseEncryption {
    /// Single public JWK used to encrypt the Credential Response.
    pub jwk: serde_json::Value,

    /// JWE `enc` algorithm to use for the encrypted Credential Response.
    pub enc: String,

    /// Optional JWE `zip` compression algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

impl CredentialResponseEncryption {
    /// Creates a new response-encryption configuration.
    pub fn new(jwk: serde_json::Value, enc: impl Into<String>) -> Self {
        Self {
            jwk,
            enc: enc.into(),
            zip: None,
        }
    }

    /// Sets the JWE `zip` compression algorithm.
    pub fn with_zip(mut self, zip: impl Into<String>) -> Self {
        self.zip = Some(zip.into());
        self
    }

    /// Validates the response-encryption configuration.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.jwk.is_object() {
            return Err(invalid_credential_request(
                "credential_response_encryption.jwk must be a JSON object",
            ));
        }

        if self.enc.is_empty() {
            return Err(invalid_credential_request(
                "credential_response_encryption.enc must not be empty",
            ));
        }

        if self.zip.as_deref().is_some_and(str::is_empty) {
            return Err(invalid_credential_request(
                "credential_response_encryption.zip must not be empty when present",
            ));
        }

        Ok(())
    }
}

/// Mutually exclusive credential selectors defined by OpenID4VCI §8.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredIdOrCredConfigId {
    #[serde(flatten)]
    inner: CredIdOrCredConfigIdInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum CredIdOrCredConfigIdInner {
    CredentialIdentifier(CredentialIdentifierField),
    CredentialConfigurationId(CredentialConfigurationIdField),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialIdentifierField {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    credential_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialConfigurationIdField {
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    credential_configuration_id: String,
}

impl CredIdOrCredConfigId {
    /// Creates a `credential_identifier` selector.
    pub fn credential_identifier(id: impl Into<String>) -> Self {
        Self {
            inner: CredIdOrCredConfigIdInner::CredentialIdentifier(CredentialIdentifierField {
                credential_identifier: id.into(),
            }),
        }
    }

    /// Creates a `credential_configuration_id` selector.
    pub fn credential_configuration_id(id: impl Into<String>) -> Self {
        Self {
            inner: CredIdOrCredConfigIdInner::CredentialConfigurationId(
                CredentialConfigurationIdField {
                    credential_configuration_id: id.into(),
                },
            ),
        }
    }

    /// Returns the `credential_identifier` value when present.
    pub fn as_credential_identifier(&self) -> Option<&str> {
        match &self.inner {
            CredIdOrCredConfigIdInner::CredentialIdentifier(field) => {
                Some(&field.credential_identifier)
            }
            CredIdOrCredConfigIdInner::CredentialConfigurationId(_) => None,
        }
    }

    /// Returns the `credential_configuration_id` value when present.
    pub fn as_credential_configuration_id(&self) -> Option<&str> {
        match &self.inner {
            CredIdOrCredConfigIdInner::CredentialIdentifier(_) => None,
            CredIdOrCredConfigIdInner::CredentialConfigurationId(field) => {
                Some(&field.credential_configuration_id)
            }
        }
    }

    fn validation_error(&self) -> Option<&'static str> {
        match &self.inner {
            CredIdOrCredConfigIdInner::CredentialIdentifier(field)
                if field.credential_identifier.is_empty() =>
            {
                Some("credential_identifier must not be empty")
            }
            CredIdOrCredConfigIdInner::CredentialConfigurationId(field)
                if field.credential_configuration_id.is_empty() =>
            {
                Some("credential_configuration_id must not be empty")
            }
            _ => None,
        }
    }

    /// Validates that the selected identifier is non-empty.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(message) = self.validation_error() {
            return Err(invalid_credential_request(message));
        }

        Ok(())
    }
}

/// The JSON body sent to the credential endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Requested credential identifier or configuration identifier.
    #[serde(flatten)]
    pub id: CredIdOrCredConfigId,

    /// Optional key proofs for credential binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,

    /// Optional parameters used to encrypt the Credential Response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

impl CredentialRequest {
    /// Creates a new credential request.
    pub fn new(id: CredIdOrCredConfigId) -> Self {
        Self {
            id,
            proofs: None,
            credential_response_encryption: None,
        }
    }

    /// Creates a request addressed by `credential_identifier`.
    pub fn from_credential_identifier(id: impl Into<String>) -> Self {
        Self::new(CredIdOrCredConfigId::credential_identifier(id))
    }

    /// Creates a request addressed by `credential_configuration_id`.
    pub fn from_credential_configuration_id(id: impl Into<String>) -> Self {
        Self::new(CredIdOrCredConfigId::credential_configuration_id(id))
    }

    /// Replaces the request `proofs` object with JWT proofs.
    pub fn with_jwt_proofs<I, S>(mut self, proofs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.proofs = Some(Proofs::jwt(proofs));
        self
    }

    /// Replaces the request `proofs` object with Data Integrity proofs.
    pub fn with_di_vp_proofs<I>(mut self, proofs: I) -> Self
    where
        I: IntoIterator<Item = serde_json::Value>,
    {
        self.proofs = Some(Proofs::di_vp(proofs));
        self
    }

    /// Replaces the request `proofs` object with a key-attestation proof.
    pub fn with_attestation_proof(mut self, attestation: impl Into<String>) -> Self {
        self.proofs = Some(Proofs::attestation(attestation));
        self
    }

    /// Replaces the request `proofs` object.
    pub fn with_proofs(mut self, proofs: Proofs) -> Self {
        self.proofs = Some(proofs);
        self
    }

    /// Sets Credential Response encryption parameters.
    pub fn with_credential_response_encryption(
        mut self,
        encryption: CredentialResponseEncryption,
    ) -> Self {
        self.credential_response_encryption = Some(encryption);
        self
    }

    /// Returns the `credential_identifier` value when present.
    pub fn credential_identifier(&self) -> Option<&str> {
        self.id.as_credential_identifier()
    }

    /// Returns the `credential_configuration_id` value when present.
    pub fn credential_configuration_id(&self) -> Option<&str> {
        self.id.as_credential_configuration_id()
    }

    /// Validates the credential request.
    pub fn validate(&self) -> Result<(), Error> {
        self.id.validate()?;

        if let Some(ref proofs) = self.proofs {
            proofs.validate()?;
        }

        if let Some(ref encryption) = self.credential_response_encryption {
            encryption.validate()?;
        }

        Ok(())
    }
}

/// Represents a deferred credential request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredCredentialRequest {
    pub transaction_id: String,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_credential_request_with_multiple_jwt_proofs() {
        let request = CredentialRequest::from_credential_configuration_id("org.iso.18013.5.1.mDL")
            .with_jwt_proofs([
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.first",
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.second",
            ])
            .with_credential_response_encryption(CredentialResponseEncryption::new(
                json!({ "kty": "EC", "crv": "P-256", "x": "abc", "y": "def" }),
                "A256GCM",
            ));

        let json = serde_json::to_value(&request).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "credential_configuration_id": "org.iso.18013.5.1.mDL",
                "proofs": {
                    "jwt": [
                        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.first",
                        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.second"
                    ]
                },
                "credential_response_encryption": {
                    "jwk": { "kty": "EC", "crv": "P-256", "x": "abc", "y": "def" },
                    "enc": "A256GCM"
                }
            })
        );
    }

    #[test]
    fn deserialize_credential_request() {
        let json = r#"{
            "credential_identifier": "credential-123",
            "proofs": {
                "jwt": ["eyJhbGciOiJFUzI1NiJ9..."]
            },
            "credential_response_encryption": {
                "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                "enc": "A256GCM",
                "zip": "DEF"
            }
        }"#;

        let request: CredentialRequest = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.credential_identifier(), Some("credential-123"));
        assert_eq!(request.credential_configuration_id(), None);

        let expected = vec!["eyJhbGciOiJFUzI1NiJ9...".to_string()];
        assert_eq!(
            request
                .proofs
                .as_ref()
                .and_then(Proofs::jwt_proofs)
                .expect("jwt proofs should be present"),
            expected.as_slice()
        );

        assert_eq!(
            request
                .credential_response_encryption
                .as_ref()
                .expect("encryption should be present")
                .zip
                .as_deref(),
            Some("DEF")
        );
    }

    #[test]
    fn deserialize_credential_request_rejects_both_identifier_fields() {
        let json = r#"{
            "credential_identifier": "credential-123",
            "credential_configuration_id": "UniversityDegree"
        }"#;

        assert!(serde_json::from_str::<CredentialRequest>(json).is_err());
    }

    #[test]
    fn deserialize_credential_request_rejects_unknown_top_level_fields() {
        let json = r#"{
            "credential_configuration_id": "UniversityDegree",
            "format": "jwt_vc_json"
        }"#;

        assert!(serde_json::from_str::<CredentialRequest>(json).is_err());
    }

    #[test]
    fn deserialize_credential_request_rejects_multiple_proof_types() {
        let json = r#"{
            "credential_configuration_id": "UniversityDegree",
            "proofs": {
                "jwt": ["valid-jwt-token"],
                "di_vp": [{"type": ["VerifiablePresentation"]}]
            }
        }"#;

        assert!(serde_json::from_str::<CredentialRequest>(json).is_err());
    }

    #[test]
    fn deserialize_credential_request_rejects_multiple_attestation_entries() {
        let json = r#"{
            "credential_configuration_id": "UniversityDegree",
            "proofs": {
                "attestation": ["attestation-1", "attestation-2"]
            }
        }"#;

        assert!(serde_json::from_str::<CredentialRequest>(json).is_err());
    }

    #[test]
    fn validate_empty_identifier() {
        let request = CredentialRequest::from_credential_identifier("");
        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_empty_jwt_proof() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_jwt_proofs([""]);
        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_invalid_di_vp_proof() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_di_vp_proofs([serde_json::Value::String("not-an-object".to_string())]);
        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_invalid_response_encryption() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_credential_response_encryption(CredentialResponseEncryption::new(
                serde_json::Value::String("not-a-jwk-object".to_string()),
                "A256GCM",
            ));

        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_valid_request() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_proofs(Proofs::jwt(["valid-jwt-token"]))
            .with_credential_response_encryption(
                CredentialResponseEncryption::new(json!({ "kty": "EC" }), "A256GCM")
                    .with_zip("DEF"),
            );

        assert!(request.validate().is_ok());
    }
}
