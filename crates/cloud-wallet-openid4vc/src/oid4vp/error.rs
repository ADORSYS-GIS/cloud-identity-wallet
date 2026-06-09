//! Error types for OID4VP (OpenID for Verifiable Presentations).
//!
//! This module defines error types specific to the OID4VP authorization flow,
//! as specified in [OpenID4VP §8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5).

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use thiserror::Error;

/// Authorization Error Response as described in [OpenID4VP §8.5].
///
/// When the Wallet encounters an error during authorization, it returns an
/// error response to the Verifier using the response mode specified in the
/// authorization request (e.g., `direct_post`).
///
/// [OpenID4VP §8.5]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5
#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationErrorResponse {
    /// The error code indicating the type of error that occurred.
    pub error: AuthorizationErrorCode,
    /// Human-readable ASCII text providing additional information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// The state value received from the Verifier, echoed back for correlation.
    /// Required if the `state` parameter was present in the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationErrorResponse {
    /// Creates a new authorization error response with the given error code.
    pub fn new(error: AuthorizationErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            state: None,
        }
    }

    /// Adds an optional human-readable description to the error response.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// Adds the state parameter to the error response.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }
}

impl Display for AuthorizationErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, "\nDescription: {desc}")?;
        }
        if let Some(state) = &self.state {
            write!(f, "\nState: {state}")?;
        }
        Ok(())
    }
}

/// Authorization Error Codes as defined in [OpenID4VP §8.5].
///
/// These error codes are used in the Authorization Error Response to indicate
/// the type of error that occurred during the presentation authorization flow.
///
/// The error codes are defined in:
/// - OAuth 2.0 [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
/// - OpenID4VP [§8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5)
///
/// [OpenID4VP §8.5]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorCode {
    /// The request is missing a required parameter, includes an invalid
    /// parameter value, includes a parameter more than once, or is otherwise
    /// malformed.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The request is missing a required parameter or is malformed")]
    InvalidRequest,

    /// The client is not authorized to request an authorization code using
    /// this method.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The client is not authorized to request an authorization code")]
    UnauthorizedClient,

    /// The resource owner or authorization server denied the request.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The resource owner or authorization server denied the request")]
    AccessDenied,

    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The authorization server does not support this response type")]
    UnsupportedResponseType,

    /// The requested scope is invalid, unknown, or malformed.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The requested scope is invalid, unknown, or malformed")]
    InvalidScope,

    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The authorization server encountered an unexpected condition")]
    ServerError,

    /// The authorization server is currently unable to handle the request
    /// due to a temporary overloading or maintenance of the server.
    ///
    /// Defined in [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)
    #[error("The authorization server is temporarily unavailable")]
    TemporarilyUnavailable,

    /// The Wallet does not have credentials matching the Presentation Definition.
    ///
    /// This is a Wallet-specific error indicating that the user does not have
    /// the credentials requested by the Verifier.
    #[error("The wallet does not have matching credentials")]
    NoMatchingCredentials,

    /// The Presentation Definition is not supported or cannot be processed.
    ///
    /// This error indicates that the Wallet cannot process the Presentation
    /// Definition provided by the Verifier.
    #[error("The presentation definition is not supported")]
    PresentationDefinitionUnsupported,

    /// The Wallet is unavailable to process the request.
    ///
    /// This error indicates that the Wallet is temporarily unavailable
    /// or cannot be reached to process the authorization request.
    #[error("The wallet is unavailable")]
    WalletUnavailable,

    /// The transaction data is invalid, malformed, contains unknown fields,
    /// has unsupported types, or references unknown credential IDs.
    ///
    /// Defined in [OpenID4VP §8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5)
    #[error("The transaction data is invalid")]
    InvalidTransactionData,
}

/// Error type for Verifier Attestation JWT validation failures.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum VerifierAttestationError {
    /// The JWT format is invalid or malformed.
    #[error("invalid JWT format: {0}")]
    InvalidFormat(String),

    /// The `typ` header parameter is missing or has an unexpected value.
    #[error("invalid 'typ' header: expected '{expected}', got '{actual}")]
    InvalidTyp { expected: String, actual: String },

    /// The issuer is not in the list of trusted attestation issuers.
    #[error("untrusted issuer: '{0}'")]
    UntrustedIssuer(String),

    /// The `sub` claim does not match the expected client_id.
    #[error("subject mismatch: expected '{expected}', got '{actual}'")]
    SubjectMismatch { expected: String, actual: String },

    /// The attestation JWT has expired.
    #[error("attestation JWT has expired")]
    Expired,

    /// The attestation JWT is not yet valid (nbf claim is in the future).
    #[error("attestation JWT is not yet valid")]
    NotYetValid,

    /// The attestation JWT has an `iat` claim in the future.
    #[error("attestation JWT has iat claim in the future")]
    IssuedInFuture,

    /// The `cnf` claim is missing or invalid.
    #[error("missing or invalid 'cnf' claim: {0}")]
    MissingCnf(String),

    /// The `cnf.jwk` claim is missing (required for Verifier's public key).
    #[error("missing 'cnf.jwk' claim")]
    MissingCnfJwk,

    /// The `response_uri` is not in the allowed list (`response_uris` claim).
    #[error("response_uri not allowed: '{0}'")]
    ResponseUriNotAllowed(String),

    /// JWT signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// The JWT claims could not be decoded.
    #[error("failed to decode JWT claims: {0}")]
    DecodingFailed(String),

    /// An error occurred during validation.
    #[error("validation error: {0}")]
    ValidationError(String),

    /// The specified key ID (kid) is not found in the issuer's JWKS.
    #[error("unknown key ID: '{0}'")]
    UnknownKeyId(String),

    /// The JWK is not a valid public key type for signature verification.
    #[error("invalid key type for signature verification: {0}")]
    InvalidKeyType(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_error_response_new() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::InvalidRequest);
        assert_eq!(error.error, AuthorizationErrorCode::InvalidRequest);
        assert!(error.error_description.is_none());
        assert!(error.state.is_none());
    }

    #[test]
    fn test_authorization_error_response_with_description() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::AccessDenied)
            .with_description("User denied the presentation request");
        assert_eq!(error.error, AuthorizationErrorCode::AccessDenied);
        assert_eq!(
            error.error_description,
            Some("User denied the presentation request".to_string())
        );
    }

    #[test]
    fn test_authorization_error_response_with_state() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::ServerError)
            .with_state("abc123");
        assert_eq!(error.error, AuthorizationErrorCode::ServerError);
        assert_eq!(error.state, Some("abc123".to_string()));
    }

    #[test]
    fn test_authorization_error_response_full() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::InvalidRequest)
            .with_description("Missing required parameter: presentation_definition")
            .with_state("xyz789");
        assert_eq!(error.error, AuthorizationErrorCode::InvalidRequest);
        assert_eq!(
            error.error_description,
            Some("Missing required parameter: presentation_definition".to_string())
        );
        assert_eq!(error.state, Some("xyz789".to_string()));
    }

    #[test]
    fn test_authorization_error_response_serialize_json() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::AccessDenied)
            .with_description("User denied")
            .with_state("test-state");

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error\":\"access_denied\""));
        assert!(json.contains("\"error_description\":\"User denied\""));
        assert!(json.contains("\"state\":\"test-state\""));
    }

    #[test]
    fn test_authorization_error_response_serialize_json_minimal() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::ServerError);
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, r#"{"error":"server_error"}"#);
    }

    #[test]
    fn test_authorization_error_response_deserialize_json() {
        let json = r#"{"error":"invalid_request","error_description":"Bad request","state":"abc"}"#;
        let error: AuthorizationErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(error.error, AuthorizationErrorCode::InvalidRequest);
        assert_eq!(error.error_description, Some("Bad request".to_string()));
        assert_eq!(error.state, Some("abc".to_string()));
    }

    #[test]
    fn test_authorization_error_response_deserialize_json_minimal() {
        let json = r#"{"error":"access_denied"}"#;
        let error: AuthorizationErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(error.error, AuthorizationErrorCode::AccessDenied);
        assert!(error.error_description.is_none());
        assert!(error.state.is_none());
    }

    #[test]
    fn test_authorization_error_code_serialize() {
        let code = AuthorizationErrorCode::InvalidRequest;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"invalid_request\"");
    }

    #[test]
    fn test_authorization_error_code_deserialize() {
        let json = "\"access_denied\"";
        let code: AuthorizationErrorCode = serde_json::from_str(json).unwrap();
        assert_eq!(code, AuthorizationErrorCode::AccessDenied);
    }

    #[test]
    fn test_authorization_error_code_display() {
        let code = AuthorizationErrorCode::InvalidRequest;
        assert_eq!(
            code.to_string(),
            "The request is missing a required parameter or is malformed"
        );
    }

    #[test]
    fn test_authorization_error_response_display() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::AccessDenied)
            .with_description("User denied")
            .with_state("test");
        let display = format!("{}", error);
        assert!(
            display
                .contains("Error: The resource owner or authorization server denied the request")
        );
        assert!(display.contains("Description: User denied"));
        assert!(display.contains("State: test"));
    }

    #[test]
    fn test_authorization_error_response_display_minimal() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::ServerError);
        let display = format!("{}", error);
        assert!(
            display.contains("Error: The authorization server encountered an unexpected condition")
        );
        assert!(!display.contains("Description:"));
        assert!(!display.contains("State:"));
    }

    #[test]
    fn test_no_matching_credentials_error() {
        let error = AuthorizationErrorResponse::new(AuthorizationErrorCode::NoMatchingCredentials)
            .with_description("User does not have the requested credential type");
        assert_eq!(error.error, AuthorizationErrorCode::NoMatchingCredentials);
        assert_eq!(
            error.error_description,
            Some("User does not have the requested credential type".to_string())
        );
    }

    #[test]
    fn test_presentation_definition_unsupported_error() {
        let error = AuthorizationErrorResponse::new(
            AuthorizationErrorCode::PresentationDefinitionUnsupported,
        )
        .with_description("Unsupported input descriptor format");
        assert_eq!(
            error.error,
            AuthorizationErrorCode::PresentationDefinitionUnsupported
        );
        assert_eq!(
            error.error_description,
            Some("Unsupported input descriptor format".to_string())
        );
    }
}
