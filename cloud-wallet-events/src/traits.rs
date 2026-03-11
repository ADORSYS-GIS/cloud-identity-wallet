//! Abstract traits for publishing and consuming events.
//!
//! These traits decouple application code from any specific message broker or
//! transport. Swap out the Kafka implementation for an in-memory bus in tests,
//! or add a new backend (NATS, RabbitMQ, …) without touching business logic.
//!
//! # Usage pattern
//!
//! ```rust,ignore
//! use wallet_events::{Publisher, Consumer, SubscriptionConfig, EventHandler};
//! use std::sync::Arc;
//!
//! async fn run(publisher: impl Publisher, consumer: impl Consumer) {
//!     // Publish one event
//!     publisher.publish(&event).await.unwrap();
//!
//!     // Subscribe and process events asynchronously
//!     let handler: EventHandler = Arc::new(|event| Box::pin(async move {
//!         println!("Received: {:?}", event);
//!         Ok(())
//!     }));
//!     consumer.subscribe(SubscriptionConfig::default(), handler).await.unwrap();
//! }
//! ```

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
///
/// Implementations must be `Send + Sync` so they can be shared across async
/// task boundaries (e.g. stored in an `Arc` and used from multiple Tokio tasks).
///
/// # Provided methods
///
/// [`publish_batch`] is provided as a default that sequentially calls
/// [`publish`] for each event. Override it when the backend supports true
/// batch sends.
///
/// [`publish_batch`]: Publisher::publish_batch
/// [`publish`]: Publisher::publish
///
/// # Example
///
/// ```rust,ignore
/// use wallet_events::{Publisher, Event, EventType};
/// use serde_json::json;
///
/// async fn emit(publisher: &impl Publisher) {
///     let event = Event::new(
///         EventType::new(EventType::KEY_CREATED),
///         json!({ "key_id": "abc" }),
///     );
///     publisher.publish(&event).await.expect("publish failed");
/// }
/// ```
#[async_trait]
pub trait Publisher: Send + Sync {
    /// Publish a single event.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::PublishError`] when the broker rejects the
    /// message or a network error occurs, and
    /// [`EventError::SerializationError`] when the event cannot be encoded.
    async fn publish(&self, event: &Event) -> Result<(), EventError>;

    /// Publish a batch of events, sequentially by default.
    ///
    /// Returns on the first error encountered. Override this method when the
    /// backing broker supports atomic or parallel batch sends.
    ///
    /// # Errors
    ///
    /// Propagates the first [`EventError`] returned by [`publish`].
    ///
    /// [`publish`]: Publisher::publish
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
    /// Returns [`EventError::ConfigurationError`] if the topic or broker
    /// configuration is invalid, or [`EventError::SubscribeError`] if the
    /// broker refuses the subscription.
    async fn subscribe(
        &self,
        config: SubscriptionConfig,
        handler: EventHandler,
    ) -> Result<(), EventError>;
}
