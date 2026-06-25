use std::error::Error as StdError;
use std::fmt;

use cloud_wallet_openid4vc::oid4vp::client::Error as Oid4vpClientError;
use cloud_wallet_openid4vc::oid4vp::error::RequestUriError;
use serde::{Deserialize, Serialize};

use crate::domain::models::credential::CredentialError;
use crate::session::SessionError;

/// Machine-readable error codes for the presentation flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationErrorCode {
    /// The raw authorization request could not be parsed or validated.
    InvalidRequest,
    /// The DCQL query in the request is invalid or malformed.
    InvalidDcqlQuery,
    /// The verifier's key could not be resolved or verified.
    KeyResolutionFailed,
    /// No matching credentials found for the DCQL query.
    NoMatchingCredentials,
    /// The wallet does not support any of the requested VP formats.
    VpFormatsNotSupported,
    /// The session was not found or has expired.
    SessionNotFound,
    /// The session is not in the expected state.
    InvalidSessionState,
    /// The VP token could not be built or sent.
    ResponseDeliveryFailed,
    /// The client identifier is invalid or unauthorized.
    InvalidClient,
    /// Fetching the request object from request_uri failed.
    RequestUriFetchFailed,
    /// The request object JWT is invalid or malformed.
    RequestObjectInvalid,
    /// An internal server error occurred.
    InternalError,
}

impl PresentationErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidDcqlQuery => "invalid_dcql_query",
            Self::KeyResolutionFailed => "key_resolution_failed",
            Self::NoMatchingCredentials => "no_matching_credentials",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::SessionNotFound => "session_not_found",
            Self::InvalidSessionState => "invalid_session_state",
            Self::ResponseDeliveryFailed => "response_delivery_failed",
            Self::InvalidClient => "invalid_client",
            Self::RequestUriFetchFailed => "request_uri_fetch_failed",
            Self::RequestObjectInvalid => "request_object_invalid",
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
        let error = match &err {
            Oid4vpClientError::InvalidRequest(_) => PresentationErrorCode::InvalidRequest,
            Oid4vpClientError::NoDcqlQuery => PresentationErrorCode::InvalidDcqlQuery,
            Oid4vpClientError::RequestUriFailed(req_uri_err) => match req_uri_err {
                RequestUriError::HttpError { .. } | RequestUriError::Transport(_) => {
                    PresentationErrorCode::RequestUriFetchFailed
                }
                _ => PresentationErrorCode::InvalidRequest,
            },
            Oid4vpClientError::InvalidRequestObject(_) => {
                PresentationErrorCode::RequestObjectInvalid
            }
            Oid4vpClientError::InvalidClientId(_) => PresentationErrorCode::InvalidClient,
            Oid4vpClientError::VerifierResolutionFailed(_) => PresentationErrorCode::InvalidClient,
            Oid4vpClientError::ValidationFailed(_) => PresentationErrorCode::InvalidRequest,
            Oid4vpClientError::UnsupportedResponseMode(_) => {
                PresentationErrorCode::ResponseDeliveryFailed
            }
            Oid4vpClientError::ResponseDeliveryFailed(_) | Oid4vpClientError::NoResponseUri => {
                PresentationErrorCode::ResponseDeliveryFailed
            }
            Oid4vpClientError::InvalidTransactionData(_) => PresentationErrorCode::InvalidRequest,
            Oid4vpClientError::PresentationBuildFailed(_) => PresentationErrorCode::InternalError,
        };
        Self {
            error,
            error_description: None,
            source: Some(Box::new(err)),
        }
    }
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
