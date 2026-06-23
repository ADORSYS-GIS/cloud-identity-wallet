use std::error::Error as StdError;
use std::fmt;

use cloud_wallet_openid4vc::oid4vp::client::Error as Oid4vpClientError;

use crate::domain::models::credential::CredentialError;
use crate::session::SessionError;

type DynError = Box<dyn StdError + Send + Sync>;

/// Machine-readable error codes for the presentation flow.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub code: PresentationErrorCode,
    pub description: Option<String>,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PresentationError {
    /// Create a new presentation error with a code and description.
    pub fn new(code: PresentationErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
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
            code: PresentationErrorCode::InternalError,
            description: None,
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
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(desc) = &self.description {
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
        let code = match &err {
            Oid4vpClientError::InvalidRequest(_) | Oid4vpClientError::NoDcqlQuery => {
                PresentationErrorCode::InvalidRequest
            }
            Oid4vpClientError::InvalidRequestObject(_)
            | Oid4vpClientError::InvalidClientId(_)
            | Oid4vpClientError::VerifierResolutionFailed(_) => {
                PresentationErrorCode::KeyResolutionFailed
            }
            Oid4vpClientError::ResponseDeliveryFailed(_)
            | Oid4vpClientError::NoResponseUri
            | Oid4vpClientError::UnsupportedResponseMode(_) => {
                PresentationErrorCode::ResponseDeliveryFailed
            }
            _ => PresentationErrorCode::InternalError,
        };
        Self {
            code,
            description: None,
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
