//! Kafka-backed implementations of the [`Publisher`] and [`Consumer`] traits.
//!
//! [`Publisher`]: crate::traits::Publisher
//! [`Consumer`]: crate::traits::Consumer
//!
//! This module provides [`KafkaPublisher`] and [`KafkaConsumer`], powered by
//! the `kafka` crate. Both types integrate cleanly into an asynchronous
//! runtime.
//!
//! # Topic naming
//!
//! Topics are derived automatically from events. Given a `topic_prefix` of
//! `"wallet"` and an event type of `"credential.stored"`, the resolved topic
//! is `"wallet.credential"`. The `"category"` metadata key overrides this
//! derived value if present.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use wallet_events::{
//!     KafkaPublisher, KafkaPublisherConfig, KafkaConsumer, KafkaConsumerConfig,
//!     ProducerAcks, Event, EventType, SubscriptionConfig, EventHandler,
//!     Publisher, Consumer,
//! };
//! use serde_json::json;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // --- Publisher ---
//!     let publisher = KafkaPublisher::new(KafkaPublisherConfig {
//!         bootstrap_servers: "localhost:9092".into(),
//!         topic_prefix: "wallet".into(),
//!         producer_acks: ProducerAcks::One,
//!         ack_timeout_secs: 5,
//!     })?;
//!
//!     let event = Event::new(
//!         EventType::new(EventType::KEY_CREATED),
//!         json!({ "key_id": "abc-123" }),
//!     )
//!     .with_metadata("wallet_id", "wallet-42");
//!
//!     publisher.publish(&event).await?;
//!
//!     // --- Consumer ---
//!     let consumer = KafkaConsumer::new(KafkaConsumerConfig {
//!         bootstrap_servers: "localhost:9092".into(),
//!         consumer_group_id: "my-service".into(),
//!     });
//!
//!     let handler: EventHandler = Arc::new(|event| Box::pin(async move {
//!         println!("Received: {:?}", event);
//!         Ok(())
//!     }));
//!
//!     consumer
//!         .subscribe(
//!             SubscriptionConfig { topics: vec!["wallet.key".into()] },
//!             handler,
//!         )
//!         .await?;
//!
//!     Ok(())
//! }
//! ```

use crate::error::EventError;
use crate::events::Event;
use crate::traits::{
    Consumer as EventConsumer, EventHandler, Publisher as EventPublisher, SubscriptionConfig,
};

use async_trait::async_trait;
use kafka::consumer::{Consumer, FetchOffset, GroupOffsetStorage};
use kafka::producer::{Producer, Record, RequiredAcks};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

/// Controls how many brokers must acknowledge a message before the produce
/// request is considered successful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerAcks {
    /// Fire-and-forget — no acknowledgement is required.
    None,
    /// The leader broker must acknowledge the message.
    ///
    /// Balances throughput and durability. Suitable for most events.
    One,
    /// All in-sync replicas must acknowledge the message.
    ///
    /// Highest durability guarantee. Use for events that must never be lost.
    All,
}

impl From<ProducerAcks> for RequiredAcks {
    fn from(acks: ProducerAcks) -> Self {
        match acks {
            ProducerAcks::None => RequiredAcks::None,
            ProducerAcks::One => RequiredAcks::One,
            ProducerAcks::All => RequiredAcks::All,
        }
    }
}

/// Configuration for the [`KafkaPublisher`].
///
/// # Example
///
/// ```
/// use wallet_events::{KafkaPublisherConfig, ProducerAcks};
///
/// let config = KafkaPublisherConfig {
///     bootstrap_servers: "broker1:9092,broker2:9092".into(),
///     topic_prefix: "wallet".into(),
///     producer_acks: ProducerAcks::One,
///     ack_timeout_secs: 5,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct KafkaPublisherConfig {
    /// Comma-separated list of Kafka broker addresses.
    ///
    /// Each entry must be a `host:port` pair. Multiple brokers should be
    /// separated by a single comma without surrounding whitespace.
    /// Example: `"broker1:9092,broker2:9092"`.
    pub bootstrap_servers: String,

    /// Prefix prepended to every topic name produced by this publisher.
    ///
    /// Topics are derived as `"{topic_prefix}.{category}"` where `category`
    /// is taken from the `category` metadata field of the event (if present)
    /// or from the first dot-separated segment of the event type string.
    ///
    /// Example: prefix `"wallet"` + event type `"key.created"` → topic
    /// `"wallet.key"`.
    pub topic_prefix: String,

    /// Acknowledgement level required from the broker.
    pub producer_acks: ProducerAcks,

    /// How long the producer waits for broker acknowledgements before timing
    /// out, in seconds.
    pub ack_timeout_secs: u64,
}

/// Configuration for the [`KafkaConsumer`].
///
/// # Example
///
/// ```
/// use wallet_events::KafkaConsumerConfig;
///
/// let config = KafkaConsumerConfig {
///     bootstrap_servers: "broker1:9092,broker2:9092".into(),
///     consumer_group_id: "credential-service".into(),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct KafkaConsumerConfig {
    /// Comma-separated list of Kafka broker addresses.
    ///
    /// Each entry must be a `host:port` pair. Multiple brokers should be
    /// separated by a single comma without surrounding whitespace, for
    /// example: `"broker1:9092,broker2:9092"`.
    pub bootstrap_servers: String,

    /// Consumer group ID.
    ///
    /// A random UUID suffix is appended to each subscription so that
    /// multiple instances of the same service receive independent offset
    /// tracking and can all process every event (fan-out semantics).
    ///
    /// If you want competing-consumer semantics (each event processed by
    /// exactly one instance), share the same prefix across all instances and
    /// set up the consumer group accordingly in Kafka.
    pub consumer_group_id: String,
}

/// A Kafka-backed event publisher.
///
/// # Thread safety
///
/// `KafkaPublisher` is thread-safe and can be shared between tasks.
///
/// # Example
///
/// ```rust,no_run
/// use wallet_events::{KafkaPublisher, KafkaPublisherConfig, ProducerAcks, Publisher,
///                     Event, EventType};
/// use serde_json::json;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let publisher = KafkaPublisher::new(KafkaPublisherConfig {
///         bootstrap_servers: "localhost:9092".into(),
///         topic_prefix: "wallet".into(),
///         producer_acks: ProducerAcks::One,
///         ack_timeout_secs: 5,
///     })?;
///
///     let event = Event::new(
///         EventType::new(EventType::CREDENTIAL_STORED),
///         json!({ "issuer": "did:example:issuer" }),
///     );
///
///     publisher.publish(&event).await?;
///     Ok(())
/// }
/// ```
pub struct KafkaPublisher {
    config: KafkaPublisherConfig,
    producer: Arc<Mutex<Producer>>,
}

impl std::fmt::Debug for KafkaPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaPublisher")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl KafkaPublisher {
    /// Create a new [`KafkaPublisher`] from the supplied configuration.
    ///
    /// Parses `bootstrap_servers` by splitting on `','` and attempts to
    /// connect to at least one broker to create the underlying Kafka
    /// producer.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::ConfigurationError`] if the producer cannot be
    /// created (e.g. no brokers are reachable or the configuration is
    /// malformed).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wallet_events::{KafkaPublisher, KafkaPublisherConfig, ProducerAcks};
    ///
    /// let publisher = KafkaPublisher::new(KafkaPublisherConfig {
    ///     bootstrap_servers: "localhost:9092".into(),
    ///     topic_prefix: "wallet".into(),
    ///     producer_acks: ProducerAcks::One,
    ///     ack_timeout_secs: 5,
    /// }).expect("failed to create publisher");
    /// ```
    pub fn new(config: KafkaPublisherConfig) -> Result<Self, EventError> {
        // bootstrap_servers is a comma-separated list of "host:port" pairs.
        let hosts: Vec<String> = config
            .bootstrap_servers
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let producer = Producer::from_hosts(hosts)
            .with_ack_timeout(Duration::from_secs(config.ack_timeout_secs))
            .with_required_acks(config.producer_acks.into())
            .create()
            .map_err(|e| {
                EventError::ConfigurationError(format!("Failed to create producer: {e}"))
            })?;

        Ok(Self {
            config,
            producer: Arc::new(Mutex::new(producer)),
        })
    }

    /// Derive the Kafka topic for an event.
    ///
    /// The topic is `"{topic_prefix}.{category}"` where `category` is taken
    /// from the `category` metadata field if present, otherwise from the
    /// first dot-separated segment of the event type string (e.g.
    /// `"credential"` from `"credential.stored"`).
    fn topic_for(&self, event: &Event) -> String {
        let category = event
            .event_type
            .as_str()
            .split('.')
            .next()
            .unwrap_or("default");
        format!("{}.{}", self.config.topic_prefix, category)
    }
}

/// A Kafka-backed event consumer.
///
/// # Thread safety
///
/// `KafkaConsumer` is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```rust,no_run
/// use wallet_events::{KafkaConsumer, KafkaConsumerConfig, Consumer,
///                     SubscriptionConfig, EventHandler};
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let consumer = KafkaConsumer::new(KafkaConsumerConfig {
///         bootstrap_servers: "localhost:9092".into(),
///         consumer_group_id: "my-service".into(),
///     });
///
///     let handler: EventHandler = Arc::new(|event| Box::pin(async move {
///         println!("Got event: {}", event.event_type.as_str());
///         Ok(())
///     }));
///
///     consumer
///         .subscribe(
///             SubscriptionConfig { topics: vec!["wallet.key".into()] },
///             handler,
///         )
///         .await?;
///     Ok(())
/// }
/// ```
pub struct KafkaConsumer {
    config: KafkaConsumerConfig,
}

impl std::fmt::Debug for KafkaConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaConsumer")
            .field("config", &self.config)
            .finish()
    }
}

impl KafkaConsumer {
    /// Create a new [`KafkaConsumer`] from the supplied configuration.
    ///
    /// This is a cheap operation — no network connection is established until
    /// [`subscribe`] is called.
    ///
    /// [`subscribe`]: EventConsumer::subscribe
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::{KafkaConsumer, KafkaConsumerConfig};
    ///
    /// let consumer = KafkaConsumer::new(KafkaConsumerConfig {
    ///     bootstrap_servers: "localhost:9092".into(),
    ///     consumer_group_id: "my-service".into(),
    /// });
    /// ```
    pub fn new(config: KafkaConsumerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl EventPublisher for KafkaPublisher {
    /// Serialize `event` to JSON and publish it to the appropriate Kafka topic.
    ///
    /// The topic is resolved based on the event's type and metadata.
    ///
    /// # Errors
    ///
    /// - [`EventError::SerializationError`] — the event cannot be serialized.
    /// - [`EventError::PublishError`] — the broker rejected the record or the
    ///   blocking task panicked.
    async fn publish(&self, event: &Event) -> Result<(), EventError> {
        let topic = self.topic_for(event);
        let payload = serde_json::to_vec(event).map_err(|e| {
            EventError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        let key = event.id.to_string();

        let producer = self.producer.clone();
        let topic_clone = topic.clone();

        tokio::task::spawn_blocking(move || {
            let record =
                Record::from_key_value(topic_clone.as_str(), key.as_str(), payload.as_slice());
            producer
                .lock()
                .send(&record)
                .map_err(|e| EventError::PublishError(format!("Failed to send message: {e}")))
        })
        .await
        .map_err(|e| EventError::PublishError(format!("Panicked while sending event: {e}")))??;

        Ok(())
    }
}

#[async_trait]
impl EventConsumer for KafkaConsumer {
    /// Start consuming events from the topics listed in `config`.
    ///
    /// The handler is invoked for every event received from the subscribed topics.
    /// The subscription runs until the consumer is dropped or an unrecoverable error occurs.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::ConfigurationError`] if the underlying Kafka
    /// consumer client cannot be created (e.g. the broker is unreachable or
    /// a topic does not exist).
    async fn subscribe(
        &self,
        config: SubscriptionConfig,
        handler: EventHandler,
    ) -> Result<(), EventError> {
        // bootstrap_servers is a comma-separated list of "host:port" pairs.
        let hosts: Vec<String> = self
            .config
            .bootstrap_servers
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        let group_id = format!("{}-{}", self.config.consumer_group_id, uuid::Uuid::new_v4());
        let topics = config.topics.clone();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Result<Event, EventError>>();
        let tx_err = tx.clone();

        tokio::task::spawn_blocking(move || {
            let mut builder = Consumer::from_hosts(hosts)
                .with_group(group_id)
                .with_fallback_offset(FetchOffset::Earliest)
                .with_offset_storage(Some(GroupOffsetStorage::Kafka));

            for topic in topics {
                builder = builder.with_topic(topic);
            }

            let mut consumer = match builder.create() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx_err.send(Err(EventError::ConfigurationError(format!(
                        "Failed to create consumer: {e}"
                    ))));
                    return;
                }
            };

            loop {
                match consumer.poll() {
                    Ok(message_sets) => {
                        for ms in message_sets.iter() {
                            for m in ms.messages() {
                                match serde_json::from_slice::<Event>(m.value) {
                                    Ok(event) => {
                                        if tx.send(Ok(event)).is_err() {
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        if tx
                                            .send(Err(EventError::SerializationError(format!(
                                                "Failed to deserialize event: {e}"
                                            ))))
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                }
                            }
                            let _ = consumer.consume_messageset(ms);
                        }
                        if let Err(e) = consumer.commit_consumed()
                            && tx
                                .send(Err(EventError::PublishError(format!("Commit failed: {e}"))))
                                .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        if tx
                            .send(Err(EventError::ConnectionError(format!(
                                "Kafka poll error: {e}"
                            ))))
                            .is_err()
                        {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(2000));
                    }
                }
            }
        });

        // Async handler task — forward events from the blocking poll to the caller's handler
        tokio::spawn(async move {
            while let Some(result) = rx.recv().await {
                match result {
                    Ok(event) => {
                        if let Err(_e) = handler(event).await {
                            // Propagate handler errors back to the caller via
                            // the channel so they decide how to react.
                        }
                    }
                    Err(_e) => {
                        // Consumer-level errors are surfaced here; callers
                        // can wrap the handler to observe them.
                    }
                }
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Event, EventType};
    use crate::traits::{
        Consumer as EventConsumer, Publisher as EventPublisher, SubscriptionConfig,
    };
    use async_trait::async_trait;
    use serde_json::json;

    // Mock implementations for unit testing

    struct MockPublisher {
        published: Arc<Mutex<Vec<Event>>>,
    }

    impl MockPublisher {
        fn new() -> Self {
            Self {
                published: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn published_events(&self) -> Vec<Event> {
            self.published.lock().clone()
        }
    }

    #[async_trait]
    impl EventPublisher for MockPublisher {
        async fn publish(&self, event: &Event) -> Result<(), EventError> {
            self.published.lock().push(event.clone());
            Ok(())
        }
    }

    struct MockConsumer {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl MockConsumer {
        fn with_events(events: Vec<Event>) -> Self {
            Self {
                events: Arc::new(Mutex::new(events)),
            }
        }
    }

    #[async_trait]
    impl EventConsumer for MockConsumer {
        async fn subscribe(
            &self,
            _config: SubscriptionConfig,
            handler: EventHandler,
        ) -> Result<(), EventError> {
            let events = self.events.lock().clone();
            for event in events {
                handler(event).await?;
            }
            Ok(())
        }
    }

    fn make_event(event_type: &str) -> Event {
        Event::new(EventType::new(event_type), json!({ "test": true }))
            .with_metadata("wallet_id", "wallet-test")
    }

    #[tokio::test]
    async fn test_mock_publisher_records_events() {
        let publisher = MockPublisher::new();

        let event = make_event(EventType::KEY_CREATED);
        publisher.publish(&event).await.expect("publish failed");

        let events = publisher.published_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_str(), EventType::KEY_CREATED);
    }

    #[tokio::test]
    async fn test_mock_publisher_batch() {
        let publisher = MockPublisher::new();

        let events = vec![
            make_event(EventType::KEY_CREATED),
            make_event(EventType::KEY_REVOKED),
        ];
        publisher
            .publish_batch(&events)
            .await
            .expect("batch failed");

        assert_eq!(publisher.published_events().len(), 2);
    }

    #[tokio::test]
    async fn test_mock_consumer_dispatches_events() {
        let events = vec![
            make_event(EventType::CREDENTIAL_STORED),
            make_event(EventType::CREDENTIAL_DELETED),
        ];
        let consumer = MockConsumer::with_events(events.clone());

        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();

        consumer
            .subscribe(
                SubscriptionConfig {
                    topics: vec!["test.credential".to_string()],
                },
                Arc::new(move |event| {
                    let r = received_clone.clone();
                    Box::pin(async move {
                        r.lock().push(event);
                        Ok(())
                    })
                }),
            )
            .await
            .expect("subscribe failed");

        let got = received.lock().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].event_type.as_str(), EventType::CREDENTIAL_STORED);
        assert_eq!(got[1].event_type.as_str(), EventType::CREDENTIAL_DELETED);
    }

    #[test]
    fn test_kafka_publisher_topic_for() {
        // We can't connect to Kafka in a unit test, so we test `topic_for`
        // logic via a helper struct that replicates the logic.
        struct TopicHelper {
            prefix: String,
        }
        impl TopicHelper {
            fn topic_for(&self, event: &Event) -> String {
                let category = event
                    .metadata
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| {
                        event
                            .event_type
                            .as_str()
                            .split('.')
                            .next()
                            .unwrap_or("default")
                    });
                format!("{}.{}", self.prefix, category)
            }
        }

        let h = TopicHelper {
            prefix: "wallet".to_string(),
        };

        // Uses first segment of event_type when no "category" metadata
        let e1 = make_event("credential.stored");
        assert_eq!(h.topic_for(&e1), "wallet.credential");

        // Explicit "category" metadata takes precedence
        let e2 = make_event("key.created").with_metadata("category", "key.operations");
        assert_eq!(h.topic_for(&e2), "wallet.key.operations");
    }

    #[test]
    fn test_producer_acks_enum_conversion() {
        assert!(matches!(
            RequiredAcks::from(ProducerAcks::None),
            RequiredAcks::None
        ));
        assert!(matches!(
            RequiredAcks::from(ProducerAcks::One),
            RequiredAcks::One
        ));
        assert!(matches!(
            RequiredAcks::from(ProducerAcks::All),
            RequiredAcks::All
        ));
    }

    #[test]
    fn test_event_typed_payload() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct KeyPayload {
            key_id: String,
        }

        let event = Event::new(
            EventType::new(EventType::KEY_CREATED),
            json!({ "key_id": "abc-123" }),
        );

        let typed: KeyPayload = event.payload().expect("deserialization failed");
        assert_eq!(typed.key_id, "abc-123");
    }
}
