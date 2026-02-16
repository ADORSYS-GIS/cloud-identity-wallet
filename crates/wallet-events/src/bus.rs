use crate::events::WalletEvent;
use crate::traits::{
    DomainEvent, EventError, EventHandler, EventPublisher, EventStream, EventSubscriber,
};
use async_trait::async_trait;
use kafka::consumer::{Consumer, FetchOffset, GroupOffsetStorage};
use kafka::producer::{Producer, Record, RequiredAcks};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error};

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
    producer: Arc<Mutex<Producer>>,
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler<WalletEvent>>>>>,
}

impl KafkaEventBus {
    pub fn new(config: KafkaEventBusConfig) -> Result<Self, EventError> {
        let hosts: Vec<String> = config
            .bootstrap_servers
            .split(',')
            .map(|s| s.to_string())
            .collect();

        let acks = match config.producer_acks.as_str() {
            "0" => RequiredAcks::None,
            "1" => RequiredAcks::One,
            _ => RequiredAcks::All,
        };

        let producer = Producer::from_hosts(hosts)
            .with_ack_timeout(Duration::from_secs(5))
            .with_required_acks(acks)
            .create()
            .map_err(|e| {
                EventError::ConfigurationError(format!("Failed to create producer: {e}"))
            })?;

        Ok(Self {
            config,
            producer: Arc::new(Mutex::new(producer)),
            handlers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn register_handler(&self, handler: Arc<dyn EventHandler<WalletEvent>>) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    fn route_to_topic(&self, category: &str) -> String {
        format!("{}.{}", self.config.topic_prefix, category)
    }

    // Helper to publish synchronously
    fn send_sync(
        producer: &mut Producer,
        topic: &str,
        key: &str,
        payload: &[u8],
    ) -> Result<(), EventError> {
        let record = Record::from_key_value(topic, key, payload);
        producer
            .send(&record)
            .map_err(|e| EventError::PublishError(format!("Failed to send message: {e}")))
    }

    pub async fn start_consuming(&self) -> Result<(), EventError> {
        let hosts: Vec<String> = self
            .config
            .bootstrap_servers
            .split(',')
            .map(|s| s.to_string())
            .collect();

        let topics = vec![
            format!("{}.credential.offers", self.config.topic_prefix),
            format!("{}.credential.issuance", self.config.topic_prefix),
            format!("{}.credential.storage", self.config.topic_prefix),
            format!("{}.presentation.requests", self.config.topic_prefix),
            format!("{}.presentation.submissions", self.config.topic_prefix),
            format!("{}.key.operations", self.config.topic_prefix),
        ];

        // We clone what we need for the blocking task
        let group_id = self.config.consumer_group_id.clone();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<WalletEvent>();

        // Spawn blocking consumer loop
        std::thread::spawn(move || {
            let mut builder = Consumer::from_hosts(hosts)
                .with_group(group_id)
                .with_fallback_offset(FetchOffset::Earliest)
                .with_offset_storage(Some(GroupOffsetStorage::Kafka));

            for topic in &topics {
                builder = builder.with_topic(topic.to_string());
            }

            let mut consumer = match builder.create() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create consumer: {e}");
                    return;
                }
            };

            loop {
                let message_sets = match consumer.poll() {
                    Ok(ms) => ms,
                    Err(e) => {
                        error!("Failed to poll Kafka: {e}");
                        continue;
                    }
                };

                for ms in message_sets.iter() {
                    for m in ms.messages() {
                        // Deserialize and send to channel
                        match serde_json::from_slice::<WalletEvent>(m.value) {
                            Ok(event) => {
                                if tx.send(event).is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                error!("Failed to deserialize: {e}");
                            }
                        }
                    }
                    let _ = consumer.consume_messageset(ms);
                }

                if let Err(e) = consumer.commit_consumed() {
                    error!("Failed to commit consumed: {e}");
                }
            }
        });

        let handlers = self.handlers.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                debug!("Received event: {}", event.event_type().as_str());
                let handlers_read = handlers.read().await;
                for handler in handlers_read.iter() {
                    if let Err(e) = handler.handle(&event).await {
                        error!("Handler handling failed: {e}");
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait]
impl EventPublisher for KafkaEventBus {
    async fn publish(&self, event: &impl DomainEvent) -> Result<(), EventError> {
        let topic = self.route_to_topic(event.topic_category());
        let payload = serde_json::to_vec(event).map_err(|e| {
            EventError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        let key = event.wallet_id();

        let producer = self.producer.clone();
        let topic_clone = topic.clone();

        tokio::task::spawn_blocking(move || {
            let mut p = producer.lock().map_err(|e| {
                EventError::PublishError(format!("Failed to acquire producer lock: {e}"))
            })?;
            Self::send_sync(&mut p, &topic_clone, &key, &payload)
        })
        .await
        .map_err(|e| EventError::PublishError(format!("Join error: {e}")))??;

        debug!("Published event {} to topic {}", event.event_type(), topic);
        Ok(())
    }

    async fn publish_batch<E: DomainEvent + Sync>(&self, events: &[E]) -> Result<(), EventError> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(())
    }
}

// Minimal implementation for Subscriber trait
#[async_trait]
impl EventSubscriber for KafkaEventBus {
    async fn subscribe<T: DomainEvent + serde::de::DeserializeOwned + Send>(
        &self,
        topic: &str,
    ) -> Result<EventStream<T>, EventError> {
        let hosts: Vec<String> = self
            .config
            .bootstrap_servers
            .split(',')
            .map(|s| s.to_string())
            .collect();
        let group_id = format!("{}-{}", self.config.consumer_group_id, uuid::Uuid::new_v4());
        let topic_name = topic.to_string();

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        std::thread::spawn(move || {
            let mut consumer = match Consumer::from_hosts(hosts)
                .with_topic(topic_name)
                .with_group(group_id)
                .with_fallback_offset(FetchOffset::Earliest)
                .with_offset_storage(Some(GroupOffsetStorage::Kafka))
                .create()
            {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Err(EventError::ConfigurationError(format!(
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
                                match serde_json::from_slice::<T>(m.value) {
                                    Ok(event) => {
                                        if tx.send(Ok(event)).is_err() {
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Err(EventError::SerializationError(
                                            format!("{e}"),
                                        )));
                                    }
                                }
                            }
                            let _ = consumer.consume_messageset(ms);
                        }
                        if let Err(e) = consumer.commit_consumed() {
                            let _ = tx
                                .send(Err(EventError::PublishError(format!("Commit failed: {e}"))));
                        }
                    }
                    Err(e) => {
                        // If topic doesn't exist yet, we wait and retry
                        eprintln!(
                            "[Subscriber] Kafka poll error: {e}. Topic might not be ready yet. Retrying..."
                        );
                        std::thread::sleep(Duration::from_millis(2000));
                    }
                }
            }
        });

        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{WalletEvent, WalletEventPayload};
    use futures::StreamExt;
    use serde::{Deserialize, Serialize};

    async fn wait_for_kafka() -> bool {
        use tokio::net::TcpStream;
        let addr = "localhost:9092";
        for _ in 0..3 {
            if TcpStream::connect(addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        false
    }

    #[test]
    fn test_kafka_config_default() {
        let config = KafkaEventBusConfig::default();
        assert_eq!(config.bootstrap_servers, "localhost:9092");
    }

    #[tokio::test]
    async fn test_publisher_interface() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let config = KafkaEventBusConfig::default();
        let bus = KafkaEventBus::new(config).expect("Failed to create event bus");

        let payload =
            WalletEventPayload::CredentialOfferSent(crate::events::CredentialOfferSentPayload {
                offer_id: "offer-1".to_string(),
                credential_issuer: "issuer-1".to_string(),
                credential_configuration_ids: vec!["conf-1".to_string()],
                grants: None,
                credential_offer_uri: None,
            });

        let event = WalletEvent::new("corr-1".to_string(), "wallet-1".to_string(), payload);

        // Test single publish
        bus.publish(&event)
            .await
            .expect("Failed to publish single event");

        // Test batch publish
        let events = vec![event.clone(), event.clone()];
        bus.publish_batch(&events)
            .await
            .expect("Failed to publish batch");
    }

    #[tokio::test]
    async fn test_subscriber_interface() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let topic = format!("test.topic.{}", uuid::Uuid::new_v4());
        let config = KafkaEventBusConfig {
            topic_prefix: "test".to_string(),
            ..Default::default()
        };
        let bus = KafkaEventBus::new(config).expect("Failed to create event bus");

        let mut stream = bus
            .subscribe::<WalletEvent>(&topic)
            .await
            .expect("Failed to subscribe");

        // Small delay to ensure consumer group is joined
        tokio::time::sleep(Duration::from_secs(2)).await;

        let payload = WalletEventPayload::KeyCreated(crate::events::KeyCreatedPayload {
            key_id: "key-1".to_string(),
            kid: "kid-1".to_string(),
            key_type: "EC".to_string(),
            key_attestation: None,
        });

        let event = WalletEvent::new("corr-2".to_string(), "wallet-2".to_string(), payload);

        // We use send_sync directly to the specific topic to test subscription
        {
            let payload = serde_json::to_vec(&event).expect("Failed to serialize event");
            let mut p = bus
                .producer
                .lock()
                .expect("Failed to acquire producer lock");
            KafkaEventBus::send_sync(&mut p, &topic, &event.wallet_id(), &payload)
                .expect("Failed to send message");
        }

        let received = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("Timeout waiting for event")
            .expect("Stream closed")
            .expect("Error in stream");

        assert_eq!(received.event_id(), event.event_id());
    }

    #[tokio::test]
    async fn test_multi_subscriber_isolation() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let topic = format!("test.multi.{}", uuid::Uuid::new_v4());
        let bus =
            KafkaEventBus::new(KafkaEventBusConfig::default()).expect("Failed to create event bus");

        let mut stream1 = bus
            .subscribe::<WalletEvent>(&topic)
            .await
            .expect("Failed to subscribe stream1");
        let mut stream2 = bus
            .subscribe::<WalletEvent>(&topic)
            .await
            .expect("Failed to subscribe stream2");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let payload = WalletEventPayload::KeyRevoked(crate::events::KeyRevokedPayload {
            key_id: "key-2".to_string(),
            kid: "kid-2".to_string(),
            revocation_reason: "compromised".to_string(),
        });

        let event = WalletEvent::new("corr-3".to_string(), "wallet-3".to_string(), payload);

        {
            let payload = serde_json::to_vec(&event).expect("Failed to serialize event");
            let mut p = bus
                .producer
                .lock()
                .expect("Failed to acquire producer lock");
            KafkaEventBus::send_sync(&mut p, &topic, &event.wallet_id(), &payload)
                .expect("Failed to send message");
        }

        let r1 = tokio::time::timeout(Duration::from_secs(10), stream1.next())
            .await
            .expect("S1 timeout")
            .expect("S1 stream error")
            .expect("S1 event error");

        let r2 = tokio::time::timeout(Duration::from_secs(10), stream2.next())
            .await
            .expect("S2 timeout")
            .expect("S2 stream error")
            .expect("S2 event error");

        assert_eq!(r1.event_id(), event.event_id());
        assert_eq!(r2.event_id(), event.event_id());
    }

    #[tokio::test]
    async fn test_custom_event_agnostic() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct CustomEvent {
            cid: String,
            payload: String,
        }

        impl DomainEvent for CustomEvent {
            fn event_type(&self) -> &str {
                "CustomEvent"
            }
            fn topic_category(&self) -> &str {
                "custom.category"
            }
            fn event_id(&self) -> String {
                "id".to_string()
            }
            fn correlation_id(&self) -> String {
                self.cid.clone()
            }
            fn wallet_id(&self) -> String {
                "wallet".to_string()
            }
            fn schema_version(&self) -> String {
                "1".to_string()
            }
        }

        let config = KafkaEventBusConfig {
            topic_prefix: "test".to_string(),
            ..Default::default()
        };
        let bus = KafkaEventBus::new(config).expect("Failed to create event bus");

        let topic = "test.custom.category";
        let mut stream = bus
            .subscribe::<CustomEvent>(topic)
            .await
            .expect("Failed to subscribe");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let event = CustomEvent {
            cid: "corr-custom".to_string(),
            payload: "hello".to_string(),
        };

        bus.publish(&event)
            .await
            .expect("Should publish custom event");

        let received = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("S1 timeout")
            .unwrap()
            .unwrap();

        assert_eq!(received.correlation_id(), "corr-custom");
        assert_eq!(received.payload, "hello");
    }
}
