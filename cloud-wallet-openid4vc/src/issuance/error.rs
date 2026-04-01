//! Credential error models for OpenID4VCI §§8.3.1, 9.3.

use serde::{Deserialize, Serialize};

/// Normative credential-endpoint error codes from OpenID4VCI §8.3.1.2.
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

/// Deferred-endpoint error codes from OpenID4VCI §9.3.
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
    use serde_json::json;

    #[test]
    fn serialize_credential_error_response() {
        let error = CredentialErrorResponse::new(CredentialErrorCode::InvalidProof)
            .with_description("The proof is invalid or missing");

        let json = serde_json::to_value(&error).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "error": "invalid_proof",
                "error_description": "The proof is invalid or missing"
            })
        );
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

    #[test]
    fn credential_error_codes_match_spec_wire_values() {
        let cases = [
            (
                CredentialErrorCode::InvalidCredentialRequest,
                "invalid_credential_request",
            ),
            (
                CredentialErrorCode::UnknownCredentialConfiguration,
                "unknown_credential_configuration",
            ),
            (
                CredentialErrorCode::UnknownCredentialIdentifier,
                "unknown_credential_identifier",
            ),
            (CredentialErrorCode::InvalidProof, "invalid_proof"),
            (CredentialErrorCode::InvalidNonce, "invalid_nonce"),
            (
                CredentialErrorCode::InvalidEncryptionParameters,
                "invalid_encryption_parameters",
            ),
            (
                CredentialErrorCode::CredentialRequestDenied,
                "credential_request_denied",
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                serde_json::to_value(code).expect("Failed to serialize"),
                serde_json::Value::String(expected.to_string())
            );
        }
    }

    #[test]
    fn deferred_error_codes_match_spec_wire_values() {
        let cases = [
            (
                DeferredCredentialErrorCode::InvalidCredentialRequest,
                "invalid_credential_request",
            ),
            (
                DeferredCredentialErrorCode::UnknownCredentialConfiguration,
                "unknown_credential_configuration",
            ),
            (
                DeferredCredentialErrorCode::UnknownCredentialIdentifier,
                "unknown_credential_identifier",
            ),
            (DeferredCredentialErrorCode::InvalidProof, "invalid_proof"),
            (DeferredCredentialErrorCode::InvalidNonce, "invalid_nonce"),
            (
                DeferredCredentialErrorCode::InvalidEncryptionParameters,
                "invalid_encryption_parameters",
            ),
            (
                DeferredCredentialErrorCode::CredentialRequestDenied,
                "credential_request_denied",
            ),
            (
                DeferredCredentialErrorCode::InvalidTransactionId,
                "invalid_transaction_id",
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                serde_json::to_value(code).expect("Failed to serialize"),
                serde_json::Value::String(expected.to_string())
            );
        }
    }
}
