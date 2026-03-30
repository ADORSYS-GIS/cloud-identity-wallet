//! Credential Request models for OpenID4VCI §8.2.

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind};

/// The `proofs` object defined by OpenID4VCI §8.2.1.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Proofs {
    /// JWT proofs — one entry per requested credential.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub jwt: Vec<String>,

    /// Data Integrity proofs — one entry per requested credential.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub di_vp: Vec<serde_json::Value>,

    /// Key attestation JWT proofs — one entry per requested credential.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attestation: Vec<String>,
}

impl Proofs {
    /// Adds a JWT proof.
    pub fn with_jwt(mut self, jwt: impl Into<String>) -> Self {
        self.jwt.push(jwt.into());
        self
    }

    /// Adds a Data Integrity proof.
    pub fn with_di_vp(mut self, di_vp: serde_json::Value) -> Self {
        self.di_vp.push(di_vp);
        self
    }

    /// Adds a key attestation proof.
    pub fn with_attestation(mut self, attestation: impl Into<String>) -> Self {
        self.attestation.push(attestation.into());
        self
    }

    /// Returns the total number of proofs across all proof types.
    pub fn len(&self) -> usize {
        self.jwt.len() + self.di_vp.len() + self.attestation.len()
    }

    /// Returns true if there are no proofs of any type.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates that at least one proof entry is present.
    ///
    /// # Errors
    ///
    /// Returns an error if no proofs are present.
    pub fn validate(&self) -> Result<(), Error> {
        if self.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "proofs must contain at least one proof entry",
            ));
        }

        let proof_type_count = usize::from(!self.jwt.is_empty())
            + usize::from(!self.di_vp.is_empty())
            + usize::from(!self.attestation.is_empty());

        if proof_type_count != 1 {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "proofs must contain exactly one non-empty proof type",
            ));
        }

        if self.jwt.iter().any(String::is_empty) {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "jwt proofs must not contain empty entries",
            ));
        }

        if self.di_vp.iter().any(|proof| !proof.is_object()) {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "di_vp proofs must contain JSON objects",
            ));
        }

        if self.attestation.len() > 1 {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "attestation proofs must contain exactly one entry when present",
            ));
        }

        if self.attestation.iter().any(String::is_empty) {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "attestation proofs must not contain empty entries",
            ));
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
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "credential_response_encryption.jwk must be a JSON object",
            ));
        }

        if self.enc.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "credential_response_encryption.enc must not be empty",
            ));
        }

        if self.zip.as_deref().is_some_and(str::is_empty) {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "credential_response_encryption.zip must not be empty when present",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct RawCredIdOrCredConfigId {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_configuration_id: Option<String>,
}

/// Mutually exclusive credential selectors defined by OpenID4VCI §8.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCredIdOrCredConfigId", into = "RawCredIdOrCredConfigId")]
pub enum CredIdOrCredConfigId {
    CredentialIdentifier { credential_identifier: String },
    CredentialConfigurationId { credential_configuration_id: String },
}

impl TryFrom<RawCredIdOrCredConfigId> for CredIdOrCredConfigId {
    type Error = String;

    fn try_from(raw: RawCredIdOrCredConfigId) -> Result<Self, Self::Error> {
        match (raw.credential_identifier, raw.credential_configuration_id) {
            (Some(credential_identifier), None) => Ok(Self::CredentialIdentifier {
                credential_identifier,
            }),
            (None, Some(credential_configuration_id)) => Ok(Self::CredentialConfigurationId {
                credential_configuration_id,
            }),
            (Some(_), Some(_)) => Err(
                "credential_identifier and credential_configuration_id are mutually exclusive"
                    .to_string(),
            ),
            (None, None) => {
                Err("credential_identifier or credential_configuration_id is required".to_string())
            }
        }
    }
}

impl From<CredIdOrCredConfigId> for RawCredIdOrCredConfigId {
    fn from(value: CredIdOrCredConfigId) -> Self {
        match value {
            CredIdOrCredConfigId::CredentialIdentifier {
                credential_identifier,
            } => Self {
                credential_identifier: Some(credential_identifier),
                credential_configuration_id: None,
            },
            CredIdOrCredConfigId::CredentialConfigurationId {
                credential_configuration_id,
            } => Self {
                credential_identifier: None,
                credential_configuration_id: Some(credential_configuration_id),
            },
        }
    }
}

impl CredIdOrCredConfigId {
    /// Creates a `credential_identifier` selector.
    pub fn credential_identifier(id: impl Into<String>) -> Self {
        Self::CredentialIdentifier {
            credential_identifier: id.into(),
        }
    }

    /// Creates a `credential_configuration_id` selector.
    pub fn credential_configuration_id(id: impl Into<String>) -> Self {
        Self::CredentialConfigurationId {
            credential_configuration_id: id.into(),
        }
    }

    /// Returns the `credential_identifier` value when present.
    pub fn as_credential_identifier(&self) -> Option<&str> {
        match self {
            Self::CredentialIdentifier {
                credential_identifier,
            } => Some(credential_identifier),
            Self::CredentialConfigurationId { .. } => None,
        }
    }

    /// Returns the `credential_configuration_id` value when present.
    pub fn as_credential_configuration_id(&self) -> Option<&str> {
        match self {
            Self::CredentialIdentifier { .. } => None,
            Self::CredentialConfigurationId {
                credential_configuration_id,
            } => Some(credential_configuration_id),
        }
    }

    /// Validates that the selected identifier is non-empty.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::CredentialIdentifier {
                credential_identifier,
            } if credential_identifier.is_empty() => Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "credential_identifier must not be empty",
            )),
            Self::CredentialConfigurationId {
                credential_configuration_id,
            } if credential_configuration_id.is_empty() => Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "credential_configuration_id must not be empty",
            )),
            _ => Ok(()),
        }
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

    /// Adds a JWT proof to the request's `proofs` object.
    pub fn with_jwt_proof(mut self, jwt: impl Into<String>) -> Self {
        self.proofs = Some(self.proofs.take().unwrap_or_default().with_jwt(jwt));
        self
    }

    /// Adds a Data Integrity proof to the request's `proofs` object.
    pub fn with_di_vp_proof(mut self, di_vp: serde_json::Value) -> Self {
        self.proofs = Some(self.proofs.take().unwrap_or_default().with_di_vp(di_vp));
        self
    }

    /// Adds a key attestation proof to the request's `proofs` object.
    pub fn with_attestation_proof(mut self, attestation: impl Into<String>) -> Self {
        self.proofs = Some(
            self.proofs
                .take()
                .unwrap_or_default()
                .with_attestation(attestation),
        );
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
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier, proofs, or encryption parameters
    /// are malformed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_credential_request_with_jwt_proof() {
        let request = CredentialRequest::from_credential_configuration_id("org.iso.18013.5.1.mDL")
            .with_jwt_proof("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...")
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
                    "jwt": ["eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."]
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
        assert_eq!(
            request.proofs.as_ref().unwrap().jwt,
            vec!["eyJhbGciOiJFUzI1NiJ9..."]
        );
        assert_eq!(
            request
                .credential_response_encryption
                .as_ref()
                .unwrap()
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

        let error = serde_json::from_str::<CredentialRequest>(json).unwrap_err();

        assert!(error.to_string().contains("mutually exclusive"));
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
            .with_jwt_proof("");
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
            .with_di_vp_proof(serde_json::Value::String("not-an-object".to_string()));
        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_multiple_attestation_proofs() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_proofs(
                Proofs::default()
                    .with_attestation("attestation-1")
                    .with_attestation("attestation-2"),
            );

        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_multiple_proof_types() {
        let request = CredentialRequest::from_credential_configuration_id("UniversityDegree")
            .with_proofs(
                Proofs::default()
                    .with_jwt("valid-jwt-token")
                    .with_di_vp(json!({"type": ["VerifiablePresentation"]})),
            );

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
            .with_proofs(Proofs::default().with_jwt("valid-jwt-token"))
            .with_credential_response_encryption(
                CredentialResponseEncryption::new(json!({ "kty": "EC" }), "A256GCM")
                    .with_zip("DEF"),
            );

        assert!(request.validate().is_ok());
    }
}
