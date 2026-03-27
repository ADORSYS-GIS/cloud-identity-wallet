//! Credential Request data models for OpenID4VCI.
//!
//! This module implements the request data models as defined in
//! [OpenID4VCI Section 8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request).

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind};

/// Proof type identifier.
///
/// Identifies the format of the proof provided in a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// JWT-based proof.
    ///
    /// The proof is a JWT signed by the holder's key.
    Jwt,
    /// Data Integrity Proof.
    DiVp,
    /// Key attestation proof.
    Attestation,
}

/// JWT proof for credential request.
///
/// Contains a JWT signed by the holder's key to prove possession
/// of the key that will be bound to the credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtProof {
    /// The JWT proving possession of the holder's key.
    ///
    /// The JWT MUST contain an `aud` (audience) claim with the value of the
    /// Credential Issuer's identifier, and an `iat` (issued at) claim.
    /// It MAY contain a `nonce` claim obtained from the nonce endpoint.
    pub jwt: String,
}

/// Data Integrity proof for credential request.
///
/// Contains a Verifiable Presentation secured using Data Integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiVpProof {
    /// The Verifiable Presentation.
    pub di_vp: serde_json::Value,
}

/// Key attestation proof for credential request.
///
/// Contains a key attestation that proves properties about the holder's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    /// The key attestation JWT.
    pub attestation: String,
}

/// Proof object for credential request.
///
/// Contains proof of possession of a key that will be bound to the credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "proof_type", rename_all = "snake_case")]
pub enum Proof {
    /// JWT proof.
    Jwt(JwtProof),
    /// Data Integrity proof.
    DiVp(DiVpProof),
    /// Key attestation proof.
    Attestation(AttestationProof),
}

impl Proof {
    /// Returns the proof type identifier.
    pub fn proof_type(&self) -> ProofType {
        match self {
            Proof::Jwt(_) => ProofType::Jwt,
            Proof::DiVp(_) => ProofType::DiVp,
            Proof::Attestation(_) => ProofType::Attestation,
        }
    }

    /// Validates the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is empty or invalid.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Proof::Jwt(jwt) => {
                if jwt.jwt.is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidCredentialRequest,
                        "jwt proof must not be empty",
                    ));
                }
            }
            Proof::DiVp(di) => {
                if di.di_vp.is_null() {
                    return Err(Error::message(
                        ErrorKind::InvalidCredentialRequest,
                        "di_vp proof must not be empty",
                    ));
                }
            }
            Proof::Attestation(att) => {
                if att.attestation.is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidCredentialRequest,
                        "attestation proof must not be empty",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofOrProofs {
    Single { proof: Proof },
    Multiple { proofs: Proofs },
}

/// Multiple key proofs for requesting several credentials in one request.
///
/// The `proofs` field in a Credential Request allows requesting N credentials
/// with N distinct key proofs in a single call to the credential endpoint.
/// Defined in [OpenID4VCI §8.2.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request).
///
/// Mutually exclusive with `proof`.
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
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredIdOrCredConfigId {
    CredentialIdentifier { credential_identifier: String },
    CredentialConfigurationId { credential_configuration_id: String },
}

/// Credential request payload.
///
/// The request sent to the credential endpoint to obtain a credential.
/// This is the main request object defined in
/// [OpenID4VCI Section 8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The credential format identifier.
    ///
    /// Identifies the format of the credential being requested.
    /// Common values include: `jwt_vc_json`, `vc+sd-jwt`, `mso_mdoc`.
    pub format: String,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProofOrProofs>,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub id: Option<CredIdOrCredConfigId>,

    /// Verifiable Credential Type identifier (for `dc+sd-jwt` format).
    ///
    /// Specifies the type of credential being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// Document type (for `mso_mdoc` format).
    ///
    /// Specifies the mdoc doctype being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// Claims to include in the credential.
    ///
    /// Allows the wallet to request specific claims to be disclosed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

impl CredentialRequest {
    /// Creates a new credential request with the specified format.
    pub fn new(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            proof: None,
            id: None,
            vct: None,
            doctype: None,
            claims: None,
        }
    }

    /// Adds a JWT proof to the request.
    pub fn with_jwt_proof(mut self, jwt: impl Into<String>) -> Self {
        self.proof = Some(ProofOrProofs::Single {
            proof: Proof::Jwt(JwtProof { jwt: jwt.into() }),
        });
        self
    }

    pub fn with_proofs(mut self, proofs: Proofs) -> Self {
        self.proof = Some(ProofOrProofs::Multiple { proofs });
        self
    }

    /// Adds a credential identifier to the request.
    pub fn with_credential_identifier(mut self, id: impl Into<String>) -> Self {
        self.id = Some(CredIdOrCredConfigId::CredentialIdentifier {
            credential_identifier: id.into(),
        });
        self
    }

    /// Adds a credential configuration ID to the request.
    pub fn with_credential_configuration_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(CredIdOrCredConfigId::CredentialConfigurationId {
            credential_configuration_id: id.into(),
        });
        self
    }

    pub fn proof(&self) -> Option<&Proof> {
        match self.proof.as_ref()? {
            ProofOrProofs::Single { proof } => Some(proof),
            ProofOrProofs::Multiple { .. } => None,
        }
    }

    pub fn proofs(&self) -> Option<&Proofs> {
        match self.proof.as_ref()? {
            ProofOrProofs::Single { .. } => None,
            ProofOrProofs::Multiple { proofs } => Some(proofs),
        }
    }

    /// Validates the credential request.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `format` is empty
    /// - `proof` is present but invalid
    pub fn validate(&self) -> Result<(), Error> {
        if self.format.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredentialRequest,
                "format must not be empty",
            ));
        }

        if let Some(ref p) = self.proof {
            match p {
                ProofOrProofs::Single { proof } => proof.validate()?,
                ProofOrProofs::Multiple { proofs } => proofs.validate()?,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_credential_request_with_jwt_proof() {
        let request = CredentialRequest::new("vc+sd-jwt")
            .with_jwt_proof("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...");

        let json = serde_json::to_string(&request).expect("Failed to serialize");

        assert!(json.contains("\"format\":\"vc+sd-jwt\""));
        assert!(json.contains("\"proof_type\":\"jwt\""));
        assert!(json.contains("\"jwt\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn deserialize_credential_request() {
        let json = r#"{
            "format": "vc+sd-jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": "eyJhbGciOiJFUzI1NiJ9..."
            }
        }"#;

        let request: CredentialRequest = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.format, "vc+sd-jwt");
        assert!(request.proof().is_some());

        let proof = request.proof().unwrap();
        assert_eq!(proof.proof_type(), ProofType::Jwt);
    }

    #[test]
    fn serialize_credential_request_with_vct() {
        let mut request = CredentialRequest::new("dc+sd-jwt");
        request.vct = Some("UniversityDegreeCredential".to_string());

        let json = serde_json::to_string(&request).expect("Failed to serialize");

        assert!(json.contains("\"vct\":\"UniversityDegreeCredential\""));
    }

    #[test]
    fn serialize_credential_request_with_doctype() {
        let mut request = CredentialRequest::new("mso_mdoc");
        request.doctype = Some("org.iso.18013.5.1.mDL".to_string());

        let json = serde_json::to_string(&request).expect("Failed to serialize");

        assert!(json.contains("\"doctype\":\"org.iso.18013.5.1.mDL\""));
    }

    #[test]
    fn validate_empty_format() {
        let request = CredentialRequest::new("");
        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_empty_jwt_proof() {
        let request = CredentialRequest::new("vc+sd-jwt").with_jwt_proof("");

        let result = request.validate();

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::InvalidCredentialRequest
        );
    }

    #[test]
    fn validate_valid_request() {
        let request = CredentialRequest::new("vc+sd-jwt").with_jwt_proof("valid-jwt-token");

        assert!(request.validate().is_ok());
    }

    #[test]
    fn proof_type_serialization() {
        assert_eq!(serde_json::to_string(&ProofType::Jwt).unwrap(), "\"jwt\"");
        assert_eq!(
            serde_json::to_string(&ProofType::DiVp).unwrap(),
            "\"di_vp\""
        );
        assert_eq!(
            serde_json::to_string(&ProofType::Attestation).unwrap(),
            "\"attestation\""
        );
    }

    #[test]
    fn di_vp_proof_serialization() {
        let proof = Proof::DiVp(DiVpProof {
            di_vp: serde_json::json!({"@context": "..."}),
        });

        let json = serde_json::to_string(&proof).expect("Failed to serialize");

        assert!(json.contains("\"proof_type\":\"di_vp\""));
        assert!(json.contains("\"di_vp\":{"));
    }

    #[test]
    fn attestation_proof_serialization() {
        let proof = Proof::Attestation(AttestationProof {
            attestation: "attestation-jwt".to_string(),
        });

        let json = serde_json::to_string(&proof).expect("Failed to serialize");

        assert!(json.contains("\"proof_type\":\"attestation\""));
        assert!(json.contains("\"attestation\":\"attestation-jwt\""));
    }
}
