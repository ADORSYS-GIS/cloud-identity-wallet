//! Abstract interface for publishing and consuming events.
use crate::error::EventError;
use crate::events::Event;
use async_trait::async_trait;
use futures::{Stream, future::BoxFuture};
use std::pin::Pin;
use std::sync::Arc;

/// A pinned, heap-allocated async stream of [`Event`] results.
///
/// Used as the return type for streaming consumers. Each item is either an
/// [`Event`] or an [`EventError`] that occurred while fetching it.
pub type EventStream<T> = Pin<Box<dyn Stream<Item = Result<T, EventError>> + Send>>;

/// Unified interface for publishing events to a message broker.
#[async_trait]
pub trait Publisher: Send + Sync {
    /// Publish an event.
    async fn publish(&self, event: &Event) -> Result<(), EventError>;

    /// Publish a batch of events, sequentially by default.
    ///
    /// Returns on the first error encountered. Override this method when the
    /// backing broker supports atomic or parallel batch sends.
    async fn publish_batch(&self, events: &[Event]) -> Result<(), EventError> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(())
    }
}

/// Configuration passed to [`Consumer::subscribe`] to control which topics
/// are consumed.
///
/// # Example
///
/// ```
/// use wallet_events::SubscriptionConfig;
///
/// let config = SubscriptionConfig {
///     topics: vec!["wallet.credential".into(), "wallet.key".into()],
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct SubscriptionConfig {
    /// List of fully-qualified topic names to subscribe to.
    ///
    /// Topic names follow the pattern `"{topic_prefix}.{category}"` as
    /// produced by [`KafkaPublisher`]. Pass the same prefix and desired
    /// categories here to receive the matching events.
    ///
    /// [`KafkaPublisher`]: crate::bus::kafka::KafkaPublisher
    pub topics: Vec<String>,
}

/// Asynchronous callback invoked for every consumed event.
///
/// The handler receives ownership of the [`Event`] and must return a
/// `BoxFuture` resolving to `Ok(())` on success or an [`EventError`] on
/// failure.  Returning an error causes the consumer to surface it; the
/// exact behaviour (retry, skip, stop) is determined by the consumer
/// implementation.
///
/// # Example
///
/// ```rust,ignore
/// use wallet_events::{EventHandler, EventError};
/// use std::sync::Arc;
///
/// let handler: EventHandler = Arc::new(|event| {
///     Box::pin(async move {
///         println!("Got {}", event.event_type.as_str());
///         Ok(())
///     })
/// });
/// ```
pub type EventHandler =
    Arc<dyn Fn(Event) -> BoxFuture<'static, Result<(), EventError>> + Send + Sync>;

/// Unified interface for consuming events from a message broker.
///
/// Implementations must be `Send + Sync`. Typically a long-running background
/// task drives the consumption loop; [`subscribe`] should return as soon as
/// the subscription is set up, delegating actual processing to one or more
/// spawned tasks.
///
/// [`subscribe`]: Consumer::subscribe
///
/// # Example
///
/// ```rust,ignore
/// use wallet_events::{Consumer, SubscriptionConfig, EventHandler};
/// use std::sync::Arc;
///
/// async fn listen(consumer: &impl Consumer) {
///     let handler: EventHandler = Arc::new(|event| Box::pin(async move {
///         println!("event: {:?}", event);
///         Ok(())
///     }));
///
///     consumer
///         .subscribe(
///             SubscriptionConfig { topics: vec!["wallet.key".into()] },
///             handler,
///         )
///         .await
///         .expect("subscribe failed");
/// }
/// ```
#[async_trait]
pub trait Consumer: Send + Sync {
    /// Subscribe to the topics listed in `config` and invoke `handler` for
    /// every received event.
    ///
    /// The method returns as soon as the subscription is established.
    /// The actual event loop runs in a background task and continues until
    /// the consumer is dropped or an unrecoverable error occurs.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::Configuration`] if the topic or broker
    /// configuration is invalid, or [`EventError::Subscribe`] if the
    /// broker refuses the subscription.
    async fn subscribe(
        &self,
        config: SubscriptionConfig,
        handler: EventHandler,
    ) -> Result<(), EventError>;
}
