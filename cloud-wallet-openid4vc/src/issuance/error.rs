use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

/// All errors that can occur during an OpenID4VCI issuance flow.
#[derive(Debug, Error, Serialize, Deserialize)]
pub struct Oid4vciError<T> {
    /// The spec-defined error code.
    pub error: T,
    /// Optional human-readable description of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
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

/// Authorization Error Response as described in [RFC 6749 §4.1.2.1]
///
/// [RFC 6749 §4.1.2.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
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

/// Token Error Response as described in [RFC 6749 §5.2] and extended in [OpenID4VCI §6.3]
///
/// [RFC 6749 §5.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
/// [OpenID4VCI §6.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-error-response
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

        assert_eq!(json_body, expected);
    }
}
