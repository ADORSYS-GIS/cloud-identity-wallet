//! Error types for the event bus system.

use thiserror::Error;

/// Errors that can occur while publishing or consuming events.
#[derive(Debug, Error)]
pub enum EventError {
    /// The broker rejected the event or the network write failed.
    #[error("Failed to publish event: {0}")]
    Publish(String),

    /// The consumer could not be registered with the broker.
    #[error("Failed to subscribe: {0}")]
    Subscribe(String),

    /// An event could not be serialized to JSON or deserialized from JSON.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The underlying transport could not reach the broker.
    #[error("Connection error: {0}")]
    Connection(String),

    /// A required configuration value is missing or invalid.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// The user-supplied [`EventHandler`] returned an error.
    ///
    /// [`EventHandler`]: crate::traits::EventHandler
    #[error("Handler error: {0}")]
    Handler(String),
}
