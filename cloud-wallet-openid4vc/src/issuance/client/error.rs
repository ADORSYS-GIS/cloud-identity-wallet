use std::borrow::Cow;

use crate::errors::{Error, ErrorKind};
use crate::issuance::error::{
    AuthzErrorResponse, CredentialErrorResponse, DeferredCredentialErrorResponse,
    NotificationErrorResponse, Oid4vciError, TokenErrorResponse,
};

/// Errors that can occur during OID4VCI client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Authorization endpoint returned an error response.
    ///
    /// Per RFC 6749 §4.1.2.1 and OID4VCI §5.2.
    #[error("authorization error: {0}")]
    Authorization(Oid4vciError<AuthzErrorResponse>),

    /// Token endpoint returned an error response.
    ///
    /// Per RFC 6749 §5.2 and OID4VCI §6.3.
    #[error("token error: {0}")]
    Token(Oid4vciError<TokenErrorResponse>),

    /// Credential endpoint returned an error response.
    ///
    /// Per OID4VCI §8.3.1.2.
    #[error("credential error: {0}")]
    Credential(Oid4vciError<CredentialErrorResponse>),

    /// Deferred credential endpoint returned an error response.
    ///
    /// Per OID4VCI §9.3.
    #[error("deferred credential error: {0}")]
    DeferredCredential(Oid4vciError<DeferredCredentialErrorResponse>),

    /// Notification endpoint returned an error response.
    ///
    /// Per OID4VCI §11.3.
    #[error("notification error: {0}")]
    Notification(Oid4vciError<NotificationErrorResponse>),

    /// Network or HTTP transport error.
    ///
    /// This includes connection failures, timeouts, DNS errors, TLS errors,
    /// and non-success HTTP status codes where the response body could not
    /// be parsed as a protocol error.
    #[error("http error")]
    Http {
        message: Option<Cow<'static, str>>,
        status: Option<u16>,
        body: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Invalid or malformed response from server.
    #[error("invalid response: {message}")]
    InvalidResponse { message: Cow<'static, str> },

    /// Validation failed for input data.
    #[error("validation error: {message}")]
    Validation { message: Cow<'static, str> },

    /// Configuration error (e.g., missing required endpoint).
    #[error("configuration error: {message}")]
    Configuration { message: Cow<'static, str> },

    /// The credential configuration ID was not found in issuer metadata.
    #[error("unknown credential configuration: {id}")]
    UnknownCredentialConfiguration { id: String },

    /// No supported grant type found in credential offer or issuer metadata.
    #[error("no supported grant type found")]
    NoSupportedGrantType,

    /// Issuer metadata discovery failed (invalid or missing metadata).
    #[error("metadata discovery failed: {message}")]
    MetadataDiscovery { message: Cow<'static, str> },

    /// Internal error that shouldn't happen (implementation bug or unexpected state).
    #[error("internal error: {message}")]
    Internal { message: Cow<'static, str> },
}

impl ClientError {
    /// Creates an HTTP error from a source error.
    pub fn http<E>(message: impl Into<Cow<'static, str>>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Http {
            message: Some(message.into()),
            status: None,
            body: None,
            source: Some(Box::new(source)),
        }
    }

    /// Creates a simple HTTP error without source.
    pub fn http_response(status: u16, body: String) -> Self {
        Self::Http {
            message: None,
            status: Some(status),
            body: Some(body),
            source: None,
        }
    }

    /// Creates a validation error.
    pub fn validation(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Creates a configuration error.
    pub fn configuration(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Creates a metadata discovery error.
    pub fn metadata(message: impl Into<Cow<'static, str>>) -> Self {
        Self::MetadataDiscovery {
            message: message.into(),
        }
    }

    /// Creates an internal error.
    pub fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

impl From<Error> for ClientError {
    fn from(err: Error) -> Self {
        match err.kind() {
            ErrorKind::InvalidCredentialOffer => {
                ClientError::validation(format!("invalid credential offer: {err}"))
            }
            ErrorKind::InvalidIssuerMetadata => {
                ClientError::metadata(format!("invalid issuer metadata: {err}"))
            }
            ErrorKind::InvalidAuthorizationServerMetadata => {
                ClientError::metadata(format!("invalid AS metadata: {err}"))
            }
            ErrorKind::InvalidAuthorizationResponse => {
                ClientError::validation(format!("invalid authorization response: {err}"))
            }
            ErrorKind::InvalidTokenRequest => {
                ClientError::validation(format!("invalid token request: {err}"))
            }
            ErrorKind::InvalidTokenResponse => ClientError::InvalidResponse {
                message: format!("invalid token response: {err}").into(),
            },
            ErrorKind::InvalidCredentialRequest => {
                ClientError::validation(format!("invalid credential request: {err}"))
            }
            ErrorKind::CredentialOfferFetchFailed => ClientError::Http {
                message: Some("failed to fetch credential offer".into()),
                status: None,
                body: None,
                source: None,
            },
            ErrorKind::HttpRequestFailed => ClientError::Http {
                message: Some("HTTP request failed".into()),
                status: None,
                body: None,
                source: None,
            },
            _ => ClientError::internal(format!("{err}")),
        }
    }
}
