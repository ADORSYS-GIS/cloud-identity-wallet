use crate::events::Event;
use async_trait::async_trait;
use futures::{Stream, future::BoxFuture};
use std::pin::Pin;
use std::sync::Arc;
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
    async fn publish_batch(&self, events: &[Event]) -> Result<(), EventError> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(())
    }
}

/// Configuration for event subscription
#[derive(Debug, Clone, Default)]
pub struct SubscriptionConfig {
    /// List of topics to subscribe to
    pub topics: Vec<String>,
}

/// Callback for handling consumed events
pub type EventHandler =
    Arc<dyn Fn(Event) -> BoxFuture<'static, Result<(), EventError>> + Send + Sync>;

/// Unified interface for consuming events
#[async_trait]
pub trait Consumer: Send + Sync {
    /// Subscribe to events based on config and handle them via callback
    async fn subscribe(
        &self,
        config: SubscriptionConfig,
        handler: EventHandler,
    ) -> Result<(), EventError>;
}
