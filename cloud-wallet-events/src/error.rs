//! Error types for the event bus system.

use thiserror::Error;

/// Errors that can occur while publishing or consuming events.
///
/// All variants carry a human-readable description of the underlying cause.
/// Use [`std::error::Error::source`] to inspect the root error when you need
/// programmatic access beyond the formatted message.
#[derive(Debug, Error)]
pub enum EventError {
    /// The broker rejected the event or the network write failed.
    ///
    /// Wraps a description of the underlying transport error (e.g.
    /// `"Failed to send message: connection refused"`).
    #[error("Failed to publish event: {0}")]
    PublishError(String),

    /// The consumer could not be registered with the broker.
    ///
    /// Typically caused by a bad topic name, an unreachable broker, or an
    /// invalid consumer-group configuration.
    #[error("Failed to subscribe: {0}")]
    SubscribeError(String),

    /// An event could not be serialized to JSON or deserialized from JSON.
    ///
    /// This usually indicates a mismatch between the event schema expected by
    /// the consumer and the bytes stored on the broker.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// The underlying transport could not reach the broker.
    ///
    /// Inspect the inner string for the broker address and the reason
    /// (e.g. `"Kafka poll error: BrokerTransportFailure"`).
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// A required configuration value is missing or invalid.
    ///
    /// This error is returned during construction of a [`KafkaPublisher`] or
    /// [`KafkaConsumer`] if the provided config is not sufficient to establish
    /// a producer or consumer client.
    ///
    /// [`KafkaPublisher`]: crate::bus::kafka::KafkaPublisher
    /// [`KafkaConsumer`]: crate::bus::kafka::KafkaConsumer
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// The user-supplied [`EventHandler`] returned an error.
    ///
    /// The inner string contains the error reported by the handler.
    ///
    /// [`EventHandler`]: crate::traits::EventHandler
    #[error("Handler error: {0}")]
    HandlerError(String),
}
