use async_trait::async_trait;
use futures::Stream;
use serde::{Serialize, de::DeserializeOwned};
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

/// Trait for domain events
pub trait DomainEvent: Serialize + Send + Sync + 'static {
    fn event_type(&self) -> &str;
    fn topic_category(&self) -> &str;
    fn event_id(&self) -> String;
    fn correlation_id(&self) -> String;
    fn wallet_id(&self) -> String;
    fn schema_version(&self) -> String;
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: &impl DomainEvent) -> Result<(), EventError>;
    async fn publish_batch<E: DomainEvent + Sync>(&self, events: &[E]) -> Result<(), EventError>;
}

#[async_trait]
pub trait EventSubscriber: Send + Sync {
    async fn subscribe<T: DomainEvent + DeserializeOwned + Send>(
        &self,
        topic: &str,
    ) -> Result<EventStream<T>, EventError>;
}

#[async_trait]
pub trait EventHandler<T: DomainEvent>: Send + Sync {
    async fn handle(&self, event: &T) -> Result<(), EventError>;

    fn event_types(&self) -> Vec<&'static str>;

    fn name(&self) -> &'static str {
        "UnnamedHandler"
    }
}
