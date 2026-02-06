use crate::domain::events::WalletEvent;
use crate::domain::ports::{
    EventError, EventHandler, EventPublisher, EventStream, EventSubscriber, EventType,
};
use async_trait::async_trait;
use rdkafka::Message;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct KafkaEventBusConfig {
    pub bootstrap_servers: String,
    pub topic_prefix: String,
    pub consumer_group_id: String,
    pub producer_acks: String,
    pub producer_retries: u32,
    pub enable_dlq: bool,
    pub dlq_topic: String,
    pub transactional_id: Option<String>,
}

impl Default for KafkaEventBusConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: "localhost:9092".to_string(),
            topic_prefix: "wallet".to_string(),
            consumer_group_id: "wallet-event-handlers".to_string(),
            producer_acks: "all".to_string(),
            producer_retries: 3,
            enable_dlq: true,
            dlq_topic: "wallet.dlq".to_string(),
            transactional_id: None,
        }
    }
}

pub struct KafkaEventBus {
    config: KafkaEventBusConfig,
    producer: FutureProducer,
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
    transaction_lock: tokio::sync::Mutex<()>,
}

impl KafkaEventBus {
    /// Create a new Kafka event bus
    pub fn new(config: KafkaEventBusConfig) -> Result<Self, EventError> {
        let mut client_config = ClientConfig::new();
        client_config
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("message.timeout.ms", "5000")
            .set("acks", &config.producer_acks)
            .set("retries", config.producer_retries.to_string())
            .set("enable.idempotence", "true")
            .set("compression.type", "gzip");

        if let Some(tid) = &config.transactional_id {
            client_config.set("transactional.id", tid);
        }

        let producer: FutureProducer = client_config.create().map_err(|e| {
            EventError::ConfigurationError(format!("Failed to create producer: {}", e))
        })?;

        if config.transactional_id.is_some() {
            producer
                .init_transactions(Duration::from_secs(10))
                .map_err(|e| {
                    EventError::ConfigurationError(format!("Failed to init transactions: {}", e))
                })?;
        }

        Ok(Self {
            config,
            producer,
            handlers: Arc::new(RwLock::new(Vec::new())),
            transaction_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Register an event handler
    pub async fn register_handler(&self, handler: Arc<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    /// Start consuming events and dispatching to handlers
    pub async fn start_consuming(&self) -> Result<(), EventError> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &self.config.bootstrap_servers)
            .set("group.id", &self.config.consumer_group_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "30000")
            .create()
            .map_err(|e| {
                EventError::ConfigurationError(format!("Failed to create consumer: {}", e))
            })?;

        // Subscribe to all wallet topics
        let topics = vec![
            format!("{}.credential.offers", self.config.topic_prefix),
            format!("{}.credential.issuance", self.config.topic_prefix),
            format!("{}.credential.storage", self.config.topic_prefix),
            format!("{}.presentation.requests", self.config.topic_prefix),
            format!("{}.presentation.submissions", self.config.topic_prefix),
            format!("{}.key.operations", self.config.topic_prefix),
        ];

        let topic_refs: Vec<&str> = topics.iter().map(|s| s.as_str()).collect();
        consumer
            .subscribe(&topic_refs)
            .map_err(|e| EventError::SubscribeError(format!("Failed to subscribe: {}", e)))?;

        info!("Started consuming from topics: {:?}", topics);

        let handlers = self.handlers.clone();
        let dlq_topic = self.config.dlq_topic.clone();
        let enable_dlq = self.config.enable_dlq;
        let producer = self.producer.clone();

        tokio::spawn(async move {
            let mut stream = consumer.stream();

            while let Some(message_result) = stream.next().await {
                match message_result {
                    Ok(message) => {
                        let payload = match message.payload() {
                            Some(p) => p,
                            None => {
                                warn!("Received message with no payload");
                                continue;
                            }
                        };

                        match serde_json::from_slice::<WalletEvent>(payload) {
                            Ok(event) => {
                                debug!("Received event: {}", event.event_type_name());

                                let handlers_read = handlers.read().await;
                                for handler in handlers_read.iter() {
                                    if let Err(e) = handler.handle(&event).await {
                                        error!("Handler {} failed: {}", handler.name(), e);
                                    }
                                }

                                if let Err(e) = consumer
                                    .commit_message(&message, rdkafka::consumer::CommitMode::Async)
                                {
                                    error!("Failed to commit offset: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to deserialize event: {}", e);

                                if enable_dlq {
                                    if let Err(dlq_err) =
                                        Self::send_to_dlq(&producer, &dlq_topic, payload).await
                                    {
                                        error!("Failed to send to DLQ: {}", dlq_err);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Kafka error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Route event to appropriate topic
    fn route_event_to_topic(&self, event: &WalletEvent) -> String {
        let topic_suffix = match event {
            WalletEvent::CredentialOfferSent(_) | WalletEvent::CredentialOfferReceived(_) => {
                "credential.offers"
            }
            WalletEvent::CredentialIssued(_) | WalletEvent::CredentialAcknowledged(_) => {
                "credential.issuance"
            }
            WalletEvent::CredentialStored(_) | WalletEvent::CredentialDeleted(_) => {
                "credential.storage"
            }
            WalletEvent::PresentationRequestSent(_)
            | WalletEvent::PresentationRequestReceived(_) => "presentation.requests",
            WalletEvent::PresentationSubmitted(_) | WalletEvent::PresentationVerified(_) => {
                "presentation.submissions"
            }
            WalletEvent::KeyCreated(_)
            | WalletEvent::KeyRotated(_)
            | WalletEvent::KeyRevoked(_) => "key.operations",
        };

        format!("{}.{}", self.config.topic_prefix, topic_suffix)
    }

    /// Send failed message to dead letter queue
    async fn send_to_dlq(
        producer: &FutureProducer,
        dlq_topic: &str,
        payload: &[u8],
    ) -> Result<(), EventError> {
        let record: FutureRecord<'_, (), _> =
            FutureRecord::to(dlq_topic)
                .payload(payload)
                .headers(OwnedHeaders::new().insert(Header {
                    key: "error",
                    value: Some("deserialization_failed"),
                }));

        producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(e, _)| EventError::PublishError(format!("Failed to send to DLQ: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl EventPublisher for KafkaEventBus {
    async fn publish(&self, event: WalletEvent) -> Result<(), EventError> {
        let topic = self.route_event_to_topic(&event);
        let metadata = event.metadata();

        // Serialize event to JSON
        let payload = serde_json::to_vec(&event).map_err(|e| {
            EventError::SerializationError(format!("Failed to serialize event: {}", e))
        })?;

        // Create message headers
        let headers = OwnedHeaders::new()
            .insert(Header {
                key: "event_type",
                value: Some(event.event_type_name()),
            })
            .insert(Header {
                key: "correlation_id",
                value: Some(&metadata.correlation_id),
            })
            .insert(Header {
                key: "wallet_id",
                value: Some(&metadata.wallet_id),
            })
            .insert(Header {
                key: "schema_version",
                value: Some(&metadata.schema_version),
            });

        let record = FutureRecord::to(&topic)
            .payload(&payload)
            .key(&metadata.wallet_id)
            .headers(headers);

        self.producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(e, _)| EventError::PublishError(format!("Failed to send message: {}", e)))?;

        debug!(
            "Published event {} to topic {}",
            event.event_type_name(),
            topic
        );

        Ok(())
    }

    async fn publish_batch(&self, events: Vec<WalletEvent>) -> Result<(), EventError> {
        if self.config.transactional_id.is_some() {
            // Serialize access to the transaction
            let _guard = self.transaction_lock.lock().await;

            self.producer.begin_transaction().map_err(|e| {
                EventError::PublishError(format!("Failed to begin transaction: {}", e))
            })?;

            for event in events {
                if let Err(e) = self.publish(event).await {
                    self.producer
                        .abort_transaction(Duration::from_secs(5))
                        .map_err(|abort_err| {
                            error!("Failed to abort transaction: {}", abort_err);
                            EventError::PublishError(format!(
                                "Publish failed: {}. Abort failed: {}",
                                e, abort_err
                            ))
                        })?;
                    return Err(e);
                }
            }

            self.producer
                .commit_transaction(Duration::from_secs(5))
                .map_err(|e| {
                    EventError::PublishError(format!("Failed to commit transaction: {}", e))
                })?;

            Ok(())
        } else {
            for event in events {
                self.publish(event).await?;
            }
            Ok(())
        }
    }
}

#[async_trait]
impl EventSubscriber for KafkaEventBus {
    async fn subscribe(&self, event_types: Vec<EventType>) -> Result<EventStream, EventError> {
        // Map event types to topics
        let mut topics = std::collections::HashSet::new();
        for event_type in event_types {
            let topic = match event_type {
                EventType::CredentialOfferSent | EventType::CredentialOfferReceived => {
                    format!("{}.credential.offers", self.config.topic_prefix)
                }
                EventType::CredentialIssued | EventType::CredentialAcknowledged => {
                    format!("{}.credential.issuance", self.config.topic_prefix)
                }
                EventType::CredentialStored | EventType::CredentialDeleted => {
                    format!("{}.credential.storage", self.config.topic_prefix)
                }
                EventType::PresentationRequestSent | EventType::PresentationRequestReceived => {
                    format!("{}.presentation.requests", self.config.topic_prefix)
                }
                EventType::PresentationSubmitted | EventType::PresentationVerified => {
                    format!("{}.presentation.submissions", self.config.topic_prefix)
                }
                EventType::KeyCreated | EventType::KeyRotated | EventType::KeyRevoked => {
                    format!("{}.key.operations", self.config.topic_prefix)
                }
            };
            topics.insert(topic);
        }

        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &self.config.bootstrap_servers)
            .set(
                "group.id",
                format!("{}-subscriber", self.config.consumer_group_id),
            )
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "earliest")
            .create()
            .map_err(|e| {
                EventError::ConfigurationError(format!("Failed to create consumer: {}", e))
            })?;

        let topic_vec: Vec<String> = topics.into_iter().collect();
        let topic_refs: Vec<&str> = topic_vec.iter().map(|s| s.as_str()).collect();
        consumer
            .subscribe(&topic_refs)
            .map_err(|e| EventError::SubscribeError(format!("Failed to subscribe: {}", e)))?;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut stream = consumer.stream();
            while let Some(msg_result) = stream.next().await {
                let event_result = match msg_result {
                    Ok(message) => match message.payload() {
                        Some(payload) => match serde_json::from_slice::<WalletEvent>(payload) {
                            Ok(event) => Ok(event),
                            Err(e) => Err(EventError::SerializationError(format!(
                                "Deserialization failed: {}",
                                e
                            ))),
                        },
                        None => continue,
                    },
                    Err(e) => Err(EventError::ConnectionError(format!("Kafka error: {}", e))),
                };

                if tx.send(event_result).is_err() {
                    break;
                }
            }
        });

        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }

    async fn subscribe_all(&self) -> Result<EventStream, EventError> {
        self.subscribe(vec![
            EventType::CredentialOfferSent,
            EventType::CredentialOfferReceived,
            EventType::CredentialIssued,
            EventType::CredentialAcknowledged,
            EventType::CredentialStored,
            EventType::CredentialDeleted,
            EventType::PresentationRequestSent,
            EventType::PresentationRequestReceived,
            EventType::PresentationSubmitted,
            EventType::PresentationVerified,
            EventType::KeyCreated,
            EventType::KeyRotated,
            EventType::KeyRevoked,
        ])
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::{CredentialOfferReceivedEvent, EventMetadata};

    #[test]
    fn test_kafka_config_default() {
        let config = KafkaEventBusConfig::default();
        assert_eq!(config.bootstrap_servers, "localhost:9092");
        assert_eq!(config.topic_prefix, "wallet");
    }

    #[test]
    fn test_route_event_to_topic() {
        let config = KafkaEventBusConfig::default();
        let bus = KafkaEventBus::new(config).unwrap();

        let event = WalletEvent::CredentialOfferReceived(CredentialOfferReceivedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            offer_id: "offer-789".to_string(),
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["UniversityDegree".to_string()],
            grants: None,
            credential_offer_uri: None,
        });

        let topic = bus.route_event_to_topic(&event);
        assert_eq!(topic, "wallet.credential.offers");
    }
}
