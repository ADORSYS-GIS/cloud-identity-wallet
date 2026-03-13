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
