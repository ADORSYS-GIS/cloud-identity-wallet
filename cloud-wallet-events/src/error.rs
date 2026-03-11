use reqwest::StatusCode;
use std::time::Duration;
use thiserror::Error;

/// Errors that can occur in the event bus system.
#[derive(Debug, Error)]
pub enum EventError {
    #[error("Failed to publish event: {0}")]
    PublishError(String),
    #[error("Failed to subscribe: {0}")]
    SubscribeError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Handler error: {0}")]
    HandlerError(String),
}

/// Errors that can occur during `DeliveryService` initialisation.
#[derive(Debug, Error)]
pub enum DeliveryServiceError {
    #[error("Initialisation failed: {0}")]
    Initialisation(String),
}

/// Errors that can occur when signing a webhook request.
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Failed to sign request: {0}")]
    SigningFailed(String),
}

/// Errors that can occur in the `EventListener`.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("Failed to subscribe: {reason}")]
    SubscribeFailed { reason: String },
}

/// Error type for HTTP client operations
#[derive(Debug, Error)]
pub enum HttpClientError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    #[error("Request timeout after {0:?}")]
    Timeout(Duration),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Response error: status={status}, body={body}")]
    ResponseError { status: StatusCode, body: String },

    #[error("Failed to sign request: {0}")]
    SignatureError(String),
}

/// Errors returned by [`HmacSigner`] and the signature header helpers.
#[derive(Debug, thiserror::Error)]
pub enum HmacSignerError {
    #[error("Failed to initialise HMAC: {0}")]
    InvalidKey(String),

    #[error("System clock error: {0}")]
    ClockError(String),

    #[error("Timestamp out of range: {0}")]
    TimestampOutOfRange(String),

    #[error("Timestamp too old: {age}s (max: {max}s)")]
    TimestampTooOld { age: u64, max: u64 },

    #[error("Timestamp is in the future: {0}s ahead")]
    TimestampInFuture(u64),

    #[error("Invalid signature: not valid hex")]
    InvalidHex,

    #[error("Invalid signature")]
    SignatureMismatch,

    #[error("Invalid X-iGrant-Signature header format: {0}")]
    InvalidHeaderFormat(String),
}

impl From<reqwest::Error> for HttpClientError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            HttpClientError::Timeout(Duration::from_secs(30))
        } else if err.is_connect() {
            HttpClientError::NetworkError(err.to_string())
        } else {
            HttpClientError::RequestFailed(err.to_string())
        }
    }
}
