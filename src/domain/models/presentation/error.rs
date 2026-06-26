use std::error::Error as StdError;
use std::fmt;

use cloud_wallet_openid4vc::oid4vp::client::Error as Oid4vpClientError;
use serde::{Deserialize, Serialize};

use crate::domain::models::credential::CredentialError;
use crate::session::SessionError;

/// Machine-readable error codes for the presentation flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationErrorCode {
    /// The raw authorization request could not be parsed or validated.
    InvalidRequest,
    /// The verifier's key could not be resolved or verified.
    KeyResolutionFailed,
    /// No matching credentials found for the DCQL query.
    NoMatchingCredentials,
    /// The session was not found or has expired.
    SessionNotFound,
    /// The session is not in the expected state.
    InvalidSessionState,
    /// Wrong credential_id or missing query_id in selection.
    InvalidCredentialSelection,
    /// Transaction data requires explicit user acknowledgment.
    TransactionDataNotAcknowledged,
    /// VP Token construction failed.
    PresentationBuildFailed,
    /// Verifier returned a non-2xx response or network error.
    VerifierSubmissionFailed,
    /// The VP token could not be built or sent.
    ResponseDeliveryFailed,
    /// An internal server error occurred.
    InternalError,
}

impl PresentationErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::KeyResolutionFailed => "key_resolution_failed",
            Self::NoMatchingCredentials => "no_matching_credentials",
            Self::SessionNotFound => "session_not_found",
            Self::InvalidSessionState => "invalid_session_state",
            Self::InvalidCredentialSelection => "invalid_credential_selection",
            Self::TransactionDataNotAcknowledged => "transaction_data_not_acknowledged",
            Self::PresentationBuildFailed => "presentation_build_failed",
            Self::VerifierSubmissionFailed => "verifier_submission_failed",
            Self::ResponseDeliveryFailed => "response_delivery_failed",
            Self::InternalError => "internal_error",
        }
    }
}

impl fmt::Display for PresentationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The unified presentation error type.
#[derive(Debug, thiserror::Error)]
pub struct PresentationError {
    pub error: PresentationErrorCode,
    pub error_description: Option<String>,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PresentationError {
    /// Create a new presentation error with a code and description.
    pub fn new(error: PresentationErrorCode, error_description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: Some(error_description.into()),
            source: None,
        }
    }

    /// Attach a source error to the presentation error.
    pub fn with_source(self, source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            source: Some(Box::new(source)),
            ..self
        }
    }

    /// Create an internal error with the given source.
    pub fn internal(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            error: PresentationErrorCode::InternalError,
            error_description: None,
            source: Some(Box::new(source)),
        }
    }

    /// Create an internal error with a message.
    pub fn internal_message(message: impl fmt::Display) -> Self {
        Self::new(PresentationErrorCode::InternalError, message.to_string())
    }

    /// Create a session not found error.
    pub fn session_not_found(session_id: &str) -> Self {
        Self::new(
            PresentationErrorCode::SessionNotFound,
            format!("Session '{session_id}' does not exist or has expired"),
        )
    }

    /// Create an invalid state error with a message.
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::new(PresentationErrorCode::InvalidSessionState, msg.into())
    }

    /// Create an invalid credential selection error.
    pub fn invalid_credential_selection(msg: impl Into<String>) -> Self {
        Self::new(
            PresentationErrorCode::InvalidCredentialSelection,
            msg.into(),
        )
    }

    /// Create a transaction-data-not-acknowledged error.
    pub fn transaction_data_not_acknowledged() -> Self {
        Self::new(
            PresentationErrorCode::TransactionDataNotAcknowledged,
            "Transaction data must be acknowledged",
        )
    }

    /// Create a verifier-submission-failed error.
    pub fn verifier_submission_failed(msg: impl Into<String>) -> Self {
        Self::new(PresentationErrorCode::VerifierSubmissionFailed, msg.into())
    }

    /// Create a presentation-build-failed error with a source.
    pub fn presentation_build_failed(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            error: PresentationErrorCode::PresentationBuildFailed,
            error_description: Some("VP Token construction failed".into()),
            source: Some(Box::new(source)),
        }
    }

    /// Returns the machine-readable presentation error code.
    pub fn error(&self) -> &str {
        self.error.as_str()
    }

    /// Returns the human-readable error details if any.
    pub fn error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, ": {desc}")?;
        }
        if let Some(source) = &self.source {
            write!(f, "\n\ncaused by:\n\t{source}")?;
        }
        Ok(())
    }
}

impl From<Oid4vpClientError> for PresentationError {
    fn from(err: Oid4vpClientError) -> Self {
        use cloud_wallet_openid4vc::oid4vp::response_mode::DirectPostError;

        let error = match &err {
            Oid4vpClientError::InvalidRequest(_) | Oid4vpClientError::NoDcqlQuery => {
                PresentationErrorCode::InvalidRequest
            }
            Oid4vpClientError::InvalidRequestObject(_)
            | Oid4vpClientError::InvalidClientId(_)
            | Oid4vpClientError::VerifierResolutionFailed(_) => {
                PresentationErrorCode::KeyResolutionFailed
            }
            Oid4vpClientError::PresentationBuildFailed(_) => {
                PresentationErrorCode::PresentationBuildFailed
            }
            Oid4vpClientError::ResponseDeliveryFailed(_) => {
                PresentationErrorCode::VerifierSubmissionFailed
            }
            Oid4vpClientError::NoResponseUri | Oid4vpClientError::UnsupportedResponseMode(_) => {
                PresentationErrorCode::ResponseDeliveryFailed
            }
            _ => PresentationErrorCode::InternalError,
        };

        let error_description = match &err {
            Oid4vpClientError::ResponseDeliveryFailed(direct_post_err) => match direct_post_err {
                DirectPostError::VerifierError { body, .. } => {
                    parse_verifier_error_description(body)
                }
                DirectPostError::HttpServerError { body, .. } => {
                    parse_verifier_error_description(body)
                }
                _ => None,
            },
            _ => None,
        };

        Self {
            error,
            error_description,
            source: Some(Box::new(err)),
        }
    }
}

/// Attempts to extract an OAuth-style `error_description` from the verifier's
/// error response body. If the body is valid JSON with an `error_description`
/// field, returns its value. Otherwise returns the raw body truncated to 256 chars.
fn parse_verifier_error_description(body: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(body) {
        if let Some(serde_json::Value::String(desc)) = map.get("error_description") {
            return Some(desc.clone());
        }
        if let Some(serde_json::Value::String(error_code)) = map.get("error") {
            return Some(error_code.clone());
        }
    }
    let truncated = if body.len() > 256 { &body[..256] } else { body };
    Some(truncated.to_string())
}

impl From<SessionError> for PresentationError {
    fn from(err: SessionError) -> Self {
        Self::internal(err)
    }
}

impl From<CredentialError> for PresentationError {
    fn from(err: CredentialError) -> Self {
        Self::internal(err)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn error_code_serializes_to_oauth_style_snake_case() {
        let json = serde_json::to_string(&PresentationErrorCode::KeyResolutionFailed).unwrap();

        assert_eq!(json, "\"key_resolution_failed\"");
    }

    #[test]
    fn internal_error_keeps_source_without_external_description() {
        let err = PresentationError::internal(std::io::Error::other("database unavailable"));

        assert_eq!(err.error(), "internal_error");
        assert!(err.error_description().is_none());
        assert!(err.source().is_some());
    }
}
