//! Credential Error Response data models for OpenID4VCI.
//!
//! This module implements the error response models as defined in
//! [OpenID4VCI Section 8.3.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response).

use serde::{Deserialize, Serialize};

/// Credential error codes.
///
/// Error codes returned by the credential endpoint.
/// Defined in [OpenID4VCI Section 8.3.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorCode {
    /// The Credential Request is missing a required parameter, includes an unsupported
    /// parameter or parameter value, repeats the same parameter, or is otherwise malformed.
    InvalidCredentialRequest,

    /// Requested Credential Configuration is unknown.
    UnknownCredentialConfiguration,

    /// Requested Credential identifier is unknown.
    UnknownCredentialIdentifier,

    /// The proofs parameter in the Credential Request is invalid.
    InvalidProof,

    /// The proofs parameter in the Credential Request uses an invalid nonce.
    InvalidNonce,

    /// The encryption parameters in the Credential Request are either invalid or missing.
    InvalidEncryptionParameters,

    /// The Credential Request has not been accepted by the Credential Issuer.
    CredentialRequestDenied,
}

impl std::fmt::Display for CredentialErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Deferred credential error codes.
///
/// Defined in [OpenID4VCI Section 9.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-error-response).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredCredentialErrorCode {
    /// The Credential Request is missing a required parameter, includes an unsupported
    /// parameter or parameter value, repeats the same parameter, or is otherwise malformed.
    InvalidCredentialRequest,

    /// Requested Credential Configuration is unknown.
    UnknownCredentialConfiguration,

    /// Requested Credential identifier is unknown.
    UnknownCredentialIdentifier,

    /// The proofs parameter in the Credential Request is invalid.
    InvalidProof,

    /// The proofs parameter in the Credential Request uses an invalid nonce.
    InvalidNonce,

    /// The encryption parameters in the Credential Request are either invalid or missing.
    InvalidEncryptionParameters,

    /// The Credential Request has not been accepted by the Credential Issuer.
    CredentialRequestDenied,

    /// The Deferred Credential Request contains an invalid `transaction_id`.
    InvalidTransactionId,
}

impl std::fmt::Display for DeferredCredentialErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Credential error response.
///
/// Error response from the credential endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialErrorResponse {
    /// The error code.
    pub error: CredentialErrorCode,

    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// Error URI with more details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl CredentialErrorResponse {
    /// Creates a new credential error response.
    pub fn new(error: CredentialErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    /// Adds an error description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }
}

impl std::fmt::Display for CredentialErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref desc) = self.error_description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CredentialErrorResponse {}

/// Deferred credential error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredCredentialErrorResponse {
    /// The error code.
    pub error: DeferredCredentialErrorCode,

    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl std::fmt::Display for DeferredCredentialErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref desc) = self.error_description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DeferredCredentialErrorResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_credential_error_response() {
        let error = CredentialErrorResponse::new(CredentialErrorCode::InvalidProof)
            .with_description("The proof is invalid or missing");

        let json = serde_json::to_string(&error).expect("Failed to serialize");

        assert!(json.contains("\"error\":\"invalid_proof\""));
        assert!(json.contains("\"error_description\":\"The proof is invalid or missing\""));
    }

    #[test]
    fn deserialize_credential_error_response() {
        let json = r#"{
            "error": "invalid_proof",
            "error_description": "The proof is invalid"
        }"#;

        let error: CredentialErrorResponse =
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(error.error, CredentialErrorCode::InvalidProof);
        assert_eq!(
            error.error_description,
            Some("The proof is invalid".to_string())
        );
        assert_eq!(error.error_uri, None);
    }

    #[test]
    fn error_code_display() {
        assert_eq!(
            format!("{}", CredentialErrorCode::InvalidProof),
            "invalid_proof"
        );
        assert_eq!(
            format!("{}", CredentialErrorCode::InvalidNonce),
            "invalid_nonce"
        );
    }

    #[test]
    fn deferred_error_code_display() {
        assert_eq!(
            format!("{}", DeferredCredentialErrorCode::InvalidProof),
            "invalid_proof"
        );
        assert_eq!(
            format!("{}", DeferredCredentialErrorCode::InvalidTransactionId),
            "invalid_transaction_id"
        );
    }
}
