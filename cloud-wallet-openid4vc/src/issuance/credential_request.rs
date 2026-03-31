//! Credential Request models for OpenID4VCI §8.2.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
};

use crate::errors::{Error, ErrorKind};

const PROOF_FIELDS: &[&str] = &["jwt", "di_vp", "attestation"];
const CREDENTIAL_REQUEST_ID_FIELDS: &[&str] =
    &["credential_identifier", "credential_configuration_id"];

fn invalid_credential_request(message: impl Into<String>) -> Error {
    Error::message(ErrorKind::InvalidCredentialRequest, message.into())
}

/// The `proofs` object defined by OpenID4VCI §8.2.1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proofs {
    /// JWT proofs for one or more requested credentials.
    Jwt(Vec<String>),
    /// Data Integrity proofs for one or more requested credentials.
    DiVp(Vec<serde_json::Value>),
    /// A single key-attestation proof.
    Attestation(String),
}

impl Proofs {
    /// Creates a `proofs.jwt` array.
    pub fn jwt<I, S>(proofs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Jwt(proofs.into_iter().map(Into::into).collect())
    }

    /// Creates a `proofs.di_vp` array.
    pub fn di_vp<I>(proofs: I) -> Self
    where
        I: IntoIterator<Item = serde_json::Value>,
    {
        Self::DiVp(proofs.into_iter().collect())
    }

    /// Creates a single-entry `proofs.attestation` array.
    pub fn attestation(attestation: impl Into<String>) -> Self {
        Self::Attestation(attestation.into())
    }

    /// Returns the total number of proof entries for the active proof type.
    pub fn len(&self) -> usize {
        match self {
            Self::Jwt(proofs) => proofs.len(),
            Self::DiVp(proofs) => proofs.len(),
            Self::Attestation(_) => 1,
        }
    }

    /// Returns true when the active proof list has no entries.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Jwt(proofs) => proofs.is_empty(),
            Self::DiVp(proofs) => proofs.is_empty(),
            Self::Attestation(_) => false,
        }
    }

    /// Returns the JWT proof entries when the active proof type is `jwt`.
    pub fn jwt_proofs(&self) -> Option<&[String]> {
        match self {
            Self::Jwt(proofs) => Some(proofs),
            Self::DiVp(_) | Self::Attestation(_) => None,
        }
    }

    /// Returns the Data Integrity proof entries when the active proof type is `di_vp`.
    pub fn di_vp_proofs(&self) -> Option<&[serde_json::Value]> {
        match self {
            Self::DiVp(proofs) => Some(proofs),
            Self::Jwt(_) | Self::Attestation(_) => None,
        }
    }

    /// Returns the attestation proof when the active proof type is `attestation`.
    pub fn attestation_proof(&self) -> Option<&str> {
        match self {
            Self::Attestation(attestation) => Some(attestation),
            Self::Jwt(_) | Self::DiVp(_) => None,
        }
    }

    fn validation_error(&self) -> Option<&'static str> {
        match self {
            Self::Jwt(proofs) if proofs.is_empty() => {
                Some("jwt proofs must contain at least one entry")
            }
            Self::Jwt(proofs) if proofs.iter().any(String::is_empty) => {
                Some("jwt proofs must not contain empty entries")
            }
            Self::DiVp(proofs) if proofs.is_empty() => {
                Some("di_vp proofs must contain at least one entry")
            }
            Self::DiVp(proofs) if proofs.iter().any(|proof| !proof.is_object()) => {
                Some("di_vp proofs must contain JSON objects")
            }
            Self::Attestation(attestation) if attestation.is_empty() => {
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

impl Serialize for Proofs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;

        match self {
            Self::Jwt(proofs) => map.serialize_entry("jwt", proofs)?,
            Self::DiVp(proofs) => map.serialize_entry("di_vp", proofs)?,
            Self::Attestation(attestation) => {
                map.serialize_entry("attestation", std::slice::from_ref(attestation))?
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Proofs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofsVisitor;

        impl<'de> Visitor<'de> for ProofsVisitor {
            type Value = Proofs;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .write_str("an object containing exactly one of jwt, di_vp, or attestation")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut proofs = None;

                while let Some(key) = map.next_key::<String>()? {
                    let next = match key.as_str() {
                        "jwt" => Proofs::jwt(map.next_value::<Vec<String>>()?),
                        "di_vp" => Proofs::di_vp(map.next_value::<Vec<serde_json::Value>>()?),
                        "attestation" => {
                            let values = map.next_value::<Vec<String>>()?;

                            match values.as_slice() {
                                [value] => Proofs::attestation(value.clone()),
                                _ => {
                                    return Err(de::Error::custom(
                                        "attestation proofs must contain exactly one entry",
                                    ));
                                }
                            }
                        }
                        _ => return Err(de::Error::unknown_field(&key, PROOF_FIELDS)),
                    };

                    if proofs.replace(next).is_some() {
                        return Err(de::Error::custom(
                            "proofs must contain exactly one proof type",
                        ));
                    }
                }

                let proofs = proofs.ok_or_else(|| {
                    de::Error::custom("proofs must contain exactly one proof type")
                })?;

                if let Some(message) = proofs.validation_error() {
                    return Err(de::Error::custom(message));
                }

                Ok(proofs)
            }
        }

        deserializer.deserialize_map(ProofsVisitor)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredIdOrCredConfigId {
    CredentialIdentifier(String),
    CredentialConfigurationId(String),
}

impl CredIdOrCredConfigId {
    /// Creates a `credential_identifier` selector.
    pub fn credential_identifier(id: impl Into<String>) -> Self {
        Self::CredentialIdentifier(id.into())
    }

    /// Creates a `credential_configuration_id` selector.
    pub fn credential_configuration_id(id: impl Into<String>) -> Self {
        Self::CredentialConfigurationId(id.into())
    }

    /// Returns the `credential_identifier` value when present.
    pub fn as_credential_identifier(&self) -> Option<&str> {
        match self {
            Self::CredentialIdentifier(id) => Some(id),
            Self::CredentialConfigurationId(_) => None,
        }
    }

    /// Returns the `credential_configuration_id` value when present.
    pub fn as_credential_configuration_id(&self) -> Option<&str> {
        match self {
            Self::CredentialIdentifier(_) => None,
            Self::CredentialConfigurationId(id) => Some(id),
        }
    }

    fn validation_error(&self) -> Option<&'static str> {
        match self {
            Self::CredentialIdentifier(id) if id.is_empty() => {
                Some("credential_identifier must not be empty")
            }
            Self::CredentialConfigurationId(id) if id.is_empty() => {
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

impl Serialize for CredIdOrCredConfigId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;

        match self {
            Self::CredentialIdentifier(id) => map.serialize_entry("credential_identifier", id)?,
            Self::CredentialConfigurationId(id) => {
                map.serialize_entry("credential_configuration_id", id)?
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CredIdOrCredConfigId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredIdOrCredConfigIdVisitor;

        impl<'de> Visitor<'de> for CredIdOrCredConfigIdVisitor {
            type Value = CredIdOrCredConfigId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "an object containing exactly one of credential_identifier or credential_configuration_id",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut credential_identifier = None;
                let mut credential_configuration_id = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "credential_identifier" => {
                            if credential_identifier.is_some() {
                                return Err(de::Error::duplicate_field("credential_identifier"));
                            }

                            credential_identifier = Some(map.next_value::<String>()?);
                        }
                        "credential_configuration_id" => {
                            if credential_configuration_id.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "credential_configuration_id",
                                ));
                            }

                            credential_configuration_id = Some(map.next_value::<String>()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                CREDENTIAL_REQUEST_ID_FIELDS,
                            ));
                        }
                    }
                }

                let id = match (credential_identifier, credential_configuration_id) {
                    (Some(_), Some(_)) => {
                        return Err(de::Error::custom(
                            "credential_identifier and credential_configuration_id are mutually exclusive",
                        ));
                    }
                    (Some(id), None) => CredIdOrCredConfigId::CredentialIdentifier(id),
                    (None, Some(id)) => CredIdOrCredConfigId::CredentialConfigurationId(id),
                    (None, None) => {
                        return Err(de::Error::custom(
                            "credential_identifier or credential_configuration_id is required",
                        ));
                    }
                };

                if let Some(message) = id.validation_error() {
                    return Err(de::Error::custom(message));
                }

                Ok(id)
            }
        }

        deserializer.deserialize_map(CredIdOrCredConfigIdVisitor)
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

        match request.proofs.as_ref().expect("proofs should be present") {
            Proofs::Jwt(jwt) => {
                assert_eq!(jwt, &vec!["eyJhbGciOiJFUzI1NiJ9...".to_string()]);
            }
            Proofs::DiVp(_) | Proofs::Attestation(_) => panic!("expected jwt proofs"),
        }

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

        let error = serde_json::from_str::<CredentialRequest>(json).unwrap_err();

        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn deserialize_credential_request_rejects_unknown_top_level_fields() {
        let json = r#"{
            "credential_configuration_id": "UniversityDegree",
            "format": "jwt_vc_json"
        }"#;

        let error = serde_json::from_str::<CredentialRequest>(json).unwrap_err();

        assert!(error.to_string().contains("unknown field"));
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

        let error = serde_json::from_str::<CredentialRequest>(json).unwrap_err();

        assert!(error.to_string().contains("exactly one proof type"));
    }

    #[test]
    fn deserialize_credential_request_rejects_multiple_attestation_entries() {
        let json = r#"{
            "credential_configuration_id": "UniversityDegree",
            "proofs": {
                "attestation": ["attestation-1", "attestation-2"]
            }
        }"#;

        let error = serde_json::from_str::<CredentialRequest>(json).unwrap_err();

        assert!(error.to_string().contains("exactly one entry"));
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
