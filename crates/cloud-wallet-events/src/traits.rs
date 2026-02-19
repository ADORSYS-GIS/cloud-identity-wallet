use crate::events::Event;
use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use thiserror::Error;

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

pub type EventStream<T> = Pin<Box<dyn Stream<Item = Result<T, EventError>> + Send>>;

/// Unified interface for publishing events
#[async_trait]
pub trait Publisher: Send + Sync {
    async fn publish(&self, event: &Event) -> Result<(), EventError>;
    async fn publish_batch(&self, events: &[Event]) -> Result<(), EventError>;
}

/// Unified interface for consuming events
#[async_trait]
pub trait Consumer: Send + Sync {
    async fn subscribe(&self, topic: &str) -> Result<EventStream<Event>, EventError>;
}

/// Interface for handling events
#[async_trait]
pub trait Handler: Send + Sync {
    async fn handle(&self, event: &Event) -> Result<(), EventError>;
    fn name(&self) -> &'static str {
        "UnnamedHandler"
    }
}
