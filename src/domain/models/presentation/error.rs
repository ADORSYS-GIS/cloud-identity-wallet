use std::fmt;

use cloud_wallet_openid4vc::oid4vp::client::Error as Oid4vpClientError;

use crate::domain::models::credential::CredentialError;
use crate::session::SessionError;

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
    /// The consent was rejected by the user.
    ConsentRejected,
    /// The VP token could not be built or sent.
    ResponseDeliveryFailed,
    /// An internal server error occurred.
    InternalError,
}

impl fmt::Display for PresentationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidRequest => "invalid_request",
            Self::KeyResolutionFailed => "key_resolution_failed",
            Self::NoMatchingCredentials => "no_matching_credentials",
            Self::SessionNotFound => "session_not_found",
            Self::InvalidSessionState => "invalid_session_state",
            Self::ConsentRejected => "consent_rejected",
            Self::ResponseDeliveryFailed => "response_delivery_failed",
            Self::InternalError => "internal_error",
        };
        f.write_str(s)
    }
}

/// The unified presentation error type.
#[derive(Debug)]
pub struct PresentationError {
    pub code: PresentationErrorCode,
    pub description: Option<String>,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PresentationError {
    pub fn new(code: PresentationErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: Some(description.into()),
            source: None,
        }
    }

    pub fn with_source(
        code: PresentationErrorCode,
        description: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            description: Some(description.into()),
            source: Some(Box::new(source)),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(PresentationErrorCode::InternalError, msg)
    }

    pub fn session_not_found(session_id: &str) -> Self {
        Self::new(
            PresentationErrorCode::SessionNotFound,
            format!("Session '{session_id}' does not exist or has expired"),
        )
    }

    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::new(PresentationErrorCode::InvalidSessionState, msg)
    }
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(ref desc) = self.description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PresentationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
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
        let description = err.to_string();
        Self {
            code,
            description: Some(description),
            source: Some(Box::new(err)),
        }
    }
}

impl From<SessionError> for PresentationError {
    fn from(err: SessionError) -> Self {
        Self::with_source(
            PresentationErrorCode::InternalError,
            "session store error",
            err,
        )
    }
}

impl From<CredentialError> for PresentationError {
    fn from(err: CredentialError) -> Self {
        Self::with_source(
            PresentationErrorCode::InternalError,
            "credential store error",
            err,
        )
    }
}
