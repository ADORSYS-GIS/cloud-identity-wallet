use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

<<<<<<< HEAD
/// All errors that can occur during an OpenID4VCI issuance flow.
#[derive(Debug, Error, Serialize, Deserialize)]
pub struct Oid4vciError<T> {
    /// The spec-defined error code.
    pub error: T,
    /// Optional human-readable description of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
=======
use super::utils::is_allowed_ascii_byte;
use serde::{Deserialize, Serialize};

/// Normative credential-endpoint error codes from OpenID4VCI Â§8.3.1.2.
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
>>>>>>> ce01eb7 (fix fmt and typo issue)
}

impl<T> Oid4vciError<T> {
    /// Creates a new error with the given error code.
    pub fn new(error: T) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    /// Adds an optional human-readable description to the error.
    pub fn with_description(self, description: impl Into<String>) -> Self {
        Self {
            error_description: Some(description.into()),
            ..self
        }
    }
}

impl<T: std::fmt::Debug> Display for Oid4vciError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {:?}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, "\nDescription: {desc}")?;
        }
        Ok(())
    }
}

/// Authorization Error Response as described in [RFC 6749 ┬º4.1.2.1]
///
/// [RFC 6749 ┬º4.1.2.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthzErrorResponse {
    #[error("The request is missing a required parameter or is malformed")]
    InvalidRequest,
    #[error("The client is not authorized to request an authorization code using this method")]
    UnauthorizedClient,
    #[error("The resource owner or authorization server denied the request")]
    AccessDenied,
    #[error(
        "The authorization server does not support obtaining an authorization code using this method"
    )]
    UnsupportedResponseType,
    #[error("The requested scope is invalid, unknown, or malformed")]
    InvalidScope,
    #[error("The authorization server encountered an unexpected condition")]
    ServerError,
    #[error("The authorization server is currently unable to handle the request")]
    TemporarilyUnavailable,
}

/// Token Error Response as described in [RFC 6749 ┬º5.2] and extended in [OpenID4VCI ┬º6.3]
///
/// [RFC 6749 ┬º5.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
/// [OpenID4VCI ┬º6.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-error-response
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenErrorResponse {
    #[error("The request is missing a required parameter or is otherwise malformed")]
    InvalidRequest,
    #[error("The provided authorization grant or refresh token is invalid/expired/revoked")]
    InvalidGrant,
    #[error("Client authentication failed")]
    InvalidClient,
    #[error("The client is not authorized for this grant type")]
    UnauthorizedClient,
    #[error("The grant type is not supported by the authorization server")]
    UnsupportedGrantType,
    #[error("The requested scope is invalid, unknown, or malformed")]
    InvalidScope,
}

/// Credential Error Response as defined in [OpenID4VCI $8.3.1.2]
///
/// [OpenID4VCI $8.3.1.2]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorResponse {
    #[error("The Credential Request is missing a required parameter or is otherwise malformed.")]
    InvalidCredentialRequest,
    #[error("The requested Credential Configuration is unknown")]
    UnknownCredentialConfiguration,
    #[error("The requested Credential Identifier is unknown")]
    UnknownCredentialIdentifier,
    #[error("The proofs parameter in the Credential Request is invalid")]
    InvalidProof,
    #[error("The proofs parameter in the Credential Request uses an invalid nonce")]
    InvalidNonce,
    #[error("Invalid or missing encryption parameters in the Credential Request")]
    InvalidEncryptionParameters,
    #[error("The Credential Request has not been accepted by the Credential Issuer")]
    CredentialRequestDenied,
}

/// Deferred Credential Error Response as described in [OpenID4VCI $9.3]
///
/// [OpenID4VCI $9.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-error-r
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredCredentialErrorResponse {
    #[error("The Credential Request is missing a required parameter or is otherwise malformed.")]
    InvalidCredentialRequest,
    #[error("The requested Credential Configuration is unknown")]
    UnknownCredentialConfiguration,
    #[error("The requested Credential Identifier is unknown")]
    UnknownCredentialIdentifier,
    #[error("The proofs parameter in the Credential Request is invalid")]
    InvalidProof,
    #[error("The proofs parameter in the Credential Request uses an invalid nonce")]
    InvalidNonce,
    #[error("Invalid or missing encryption parameters in the Credential Request")]
    InvalidEncryptionParameters,
    #[error("The Credential Request has not been accepted by the Credential Issuer")]
    CredentialRequestDenied,
    #[error("The Deferred Credential Request contains an invalid transaction_id")]
    InvalidTransactionId,
}

/// Notification Error Response as defined in [OpenID4VCI $11.3]
///
/// [OpenID4VCI $11.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationErrorResponse {
    InvalidNotificationRequest,
    InvalidNotificationId,
}

<<<<<<< HEAD
=======
impl std::fmt::Display for NotificationErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Notification error response body from OpenID4VCI Â§11.3.
///
/// Returned with HTTP 400 when the Notification Request is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationErrorResponse {
    /// The error code.
    pub error: NotificationErrorCode,

    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl NotificationErrorResponse {
    /// Creates a new notification error response.
    pub fn new(error: NotificationErrorCode) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    /// Adds an error description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// Validates that `error_description`, if present, contains only
    /// characters allowed by the specification.
    ///
    /// [OpenID4VCI §8.3.1.2] restricts `error_description` to the set
    /// `%x20-21 / %x23-5B / %x5D-7E` (printable ASCII excluding `"`
    /// and `\`).  Although §11.3 does not explicitly repeat this
    /// restriction for Notification Error Responses, the character set
    /// originates from [RFC 6750 §3] and is applied uniformly across
    /// all error responses in the specification.  Enforcing it here
    /// keeps Notification Error Responses consistent with Credential
    /// Error Responses.
    ///
    /// [OpenID4VCI §8.3.1.2]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors
    /// [RFC 6750 §3]: https://www.rfc-editor.org/rfc/rfc6750#section-3
    ///
    /// # Errors
    ///
    /// Returns an error message when `error_description` contains
    /// characters outside the allowed set.
    pub fn validate(&self) -> Result<(), String> {
      if let Some(ref desc) = self.error_description
           && let Some(pos) = desc.bytes().position(|b| !is_allowed_ascii_byte(b)) {
                return Err(format!(
                     "error_description contains disallowed character at byte offset {pos}"
                ));
             }
        
        Ok(())
    }
}

impl std::fmt::Display for NotificationErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref desc) = self.error_description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

impl std::error::Error for NotificationErrorResponse {}

>>>>>>> ce01eb7 (fix fmt and typo issue)
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_oid4vc_error() {
        let error = Oid4vciError::new(AuthzErrorResponse::InvalidRequest)
            .with_description(AuthzErrorResponse::InvalidRequest.to_string());
        let json_body = serde_json::to_value(&error).unwrap();

        let expected = json!({
            "error": "invalid_request",
            "error_description": "The request is missing a required parameter or is malformed"
        });

<<<<<<< HEAD
        assert_eq!(json_body, expected);
=======
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

    #[test]
    fn notification_error_codes_match_spec_wire_values() {
        let cases = [
            (
                NotificationErrorCode::InvalidNotificationId,
                "invalid_notification_id",
            ),
            (
                NotificationErrorCode::InvalidNotificationRequest,
                "invalid_notification_request",
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(
                serde_json::to_value(code).expect("Failed to serialize"),
                serde_json::Value::String(expected.to_string()),
            );
        }
    }

    #[test]
    fn notification_error_code_display() {
        assert_eq!(
            format!("{}", NotificationErrorCode::InvalidNotificationId),
            "invalid_notification_id"
        );
        assert_eq!(
            format!("{}", NotificationErrorCode::InvalidNotificationRequest),
            "invalid_notification_request"
        );
    }

    #[test]
    fn deserialize_notification_error_codes() {
        let cases = [
            (
                "\"invalid_notification_id\"",
                NotificationErrorCode::InvalidNotificationId,
            ),
            (
                "\"invalid_notification_request\"",
                NotificationErrorCode::InvalidNotificationRequest,
            ),
        ];

        for (input, expected) in cases {
            let code: NotificationErrorCode =
                serde_json::from_str(input).expect("Failed to deserialize");

            assert_eq!(code, expected);
        }
    }

    #[test]
    fn serialize_notification_error_response_minimal() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId);

        let json = serde_json::to_value(&response).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "error": "invalid_notification_id"
            })
        );
    }

    #[test]
    fn serialize_notification_error_response_with_description() {
        let response =
            NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationRequest)
                .with_description("missing event field");

        let json = serde_json::to_value(&response).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "error": "invalid_notification_request",
                "error_description": "missing event field"
            })
        );
    }

    /// Spec Â§11.3 â€” example error response.
    #[test]
    fn deserialize_notification_spec_error_example() {
        let json = r#"{"error": "invalid_notification_id"}"#;

        let response: NotificationErrorResponse =
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(response.error, NotificationErrorCode::InvalidNotificationId);
        assert_eq!(response.error_description, None);
    }

    #[test]
    fn notification_error_response_display() {
        let without_desc =
            NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId);

        assert_eq!(format!("{without_desc}"), "invalid_notification_id");

        let with_desc =
            NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
                .with_description("not found");

        assert_eq!(format!("{with_desc}"), "invalid_notification_id: not found");
    }

    #[test]
    fn notification_error_response_is_std_error() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId);

        let err: &dyn std::error::Error = &response;
        assert!(err.source().is_none());
    }

    #[test]
    fn notification_error_response_new_creates_without_description() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId);

        assert_eq!(response.error, NotificationErrorCode::InvalidNotificationId);
        assert_eq!(response.error_description, None);
    }

    #[test]
    fn notification_error_response_with_description_sets_value() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
            .with_description("unknown id");

        assert_eq!(response.error_description.as_deref(), Some("unknown id"));
    }

    // NotificationErrorResponse::validate

    #[test]
    fn notification_error_response_validate_none_description_succeeds() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId);

        assert!(response.validate().is_ok());
    }

    #[test]
    fn notification_error_response_validate_valid_description_succeeds() {
        let response =
            NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationRequest)
                .with_description("missing event field");

        assert!(response.validate().is_ok());
    }

    /// `\` (0x5C) is excluded from the allowed character set.
    #[test]
    fn notification_error_response_validate_backslash_fails() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
            .with_description("path\\to\\file");

        assert!(response.validate().is_err());
    }

    /// `"` (0x22) is excluded from the allowed character set.
    #[test]
    fn notification_error_response_validate_double_quote_fails() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
            .with_description("said \"hello\"");

        assert!(response.validate().is_err());
    }

    /// Control characters (0x00–0x1F) are excluded.
    #[test]
    fn notification_error_response_validate_control_char_fails() {
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
            .with_description("line\nnewline");

        assert!(response.validate().is_err());
    }

    /// Boundary characters at the edges of each allowed range must pass.
    #[test]
    fn notification_error_response_validate_boundary_chars_succeed() {
        // Space (0x20), ! (0x21), # (0x23), [ (0x5B), ] (0x5D), ~ (0x7E)
        let response = NotificationErrorResponse::new(NotificationErrorCode::InvalidNotificationId)
            .with_description(" !#[]~");

        assert!(response.validate().is_ok());
>>>>>>> ce01eb7 (fix fmt and typo issue)
    }
}
