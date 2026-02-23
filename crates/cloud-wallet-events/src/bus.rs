use crate::events::Event;
use crate::traits::{
    Consumer as EventConsumer, EventError, EventHandler, Publisher as EventPublisher,
    SubscriptionConfig,
};

use async_trait::async_trait;
use kafka::consumer::{Consumer, FetchOffset, GroupOffsetStorage};
use kafka::producer::{Producer, Record, RequiredAcks};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error};

#[derive(Debug, Clone)]
pub struct KafkaPublisherConfig {
    pub bootstrap_servers: String,
    pub topic_prefix: String,
    pub producer_acks: String,
}

impl Default for KafkaPublisherConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: "localhost:9092".to_string(),
            topic_prefix: "wallet".to_string(),
            producer_acks: "all".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KafkaConsumerConfig {
    pub bootstrap_servers: String,
    pub consumer_group_id: String,
}

impl Default for KafkaConsumerConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: "localhost:9092".to_string(),
            consumer_group_id: "wallet-event-handlers".to_string(),
        }
    }
}

pub struct KafkaPublisher {
    config: KafkaPublisherConfig,
    producer: Arc<Mutex<Producer>>,
}

impl KafkaPublisher {
    pub fn new(config: KafkaPublisherConfig) -> Result<Self, EventError> {
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
        })
    }

    /// Helper for tests or internal use to send raw bytes to a topic
    pub fn send_sync(
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
}

pub struct KafkaConsumer {
    config: KafkaConsumerConfig,
}

impl KafkaConsumer {
    pub fn new(config: KafkaConsumerConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl EventPublisher for KafkaPublisher {
    async fn publish(&self, event: &Event) -> Result<(), EventError> {
        let category = event
            .metadata
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| event.event_type.as_str());

        let topic = format!("{}.{}", self.config.topic_prefix, category);
        let payload = serde_json::to_vec(event).map_err(|e| {
            EventError::SerializationError(format!("Failed to serialize event: {e}"))
        })?;
        let key = event.id.to_string();

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

        debug!(
            "Published event {} to topic {topic}",
            event.event_type.as_str()
        );
        Ok(())
    }
}

// Minimal implementation for Subscriber trait
#[async_trait]
impl EventConsumer for KafkaConsumer {
    async fn subscribe(
        &self,
        config: SubscriptionConfig,
        handler: EventHandler,
    ) -> Result<(), EventError> {
        let hosts: Vec<String> = self
            .config
            .bootstrap_servers
            .split(',')
            .map(|s| s.to_string())
            .collect();
        let group_id = format!("{}-{}", self.config.consumer_group_id, uuid::Uuid::new_v4());
        let topics = config.topics.clone();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();

        // Blocking polling thread
        std::thread::spawn(move || {
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
                    error!("Failed to create consumer: {e}");
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
                                        if tx.send(event).is_err() {
                                            return;
                                        }
                                    }
                                    Err(e) => error!("Failed to deserialize: {e}"),
                                }
                            }
                            let _ = consumer.consume_messageset(ms);
                        }
                        if let Err(e) = consumer.commit_consumed() {
                            error!("Commit failed: {e}");
                        }
                    }
                    Err(e) => {
                        error!("Kafka poll error: {e}");
                        std::thread::sleep(Duration::from_millis(2000));
                    }
                }
            }
        });

        // Async handler task
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = handler(event).await {
                    error!("Handler error: {e}");
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
    use serde_json::json;

    use std::time::Duration;

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
        let p_config = KafkaPublisherConfig::default();
        assert_eq!(p_config.bootstrap_servers, "localhost:9092");
        let c_config = KafkaConsumerConfig::default();
        assert_eq!(c_config.bootstrap_servers, "localhost:9092");
    }

    #[tokio::test]
    async fn test_publisher_interface() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let config = KafkaPublisherConfig::default();
        let publisher = KafkaPublisher::new(config).expect("Failed to create publisher");

        let payload = json!({
            "key_id": "key-1",
            "kid": "kid-1",
            "key_type": "EC",
            "key_attestation": null,
        });

        let event = Event::new(EventType::new(EventType::KEY_CREATED), payload)
            .with_metadata("wallet_id", "wallet-1")
            .with_metadata("correlation_id", "corr-1")
            .with_metadata("category", "key.operations");

        // Test single publish
        publisher
            .publish(&event)
            .await
            .expect("Failed to publish single event");

        // Test batch publish
        let events = vec![event.clone(), event.clone()];
        publisher
            .publish_batch(&events)
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
        let p_config = KafkaPublisherConfig {
            topic_prefix: "test".to_string(),
            ..Default::default()
        };
        let c_config = KafkaConsumerConfig::default();
        let publisher = KafkaPublisher::new(p_config).expect("Failed to create publisher");
        let consumer = KafkaConsumer::new(c_config);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let config = SubscriptionConfig {
            topics: vec![topic.clone()],
        };
        consumer
            .subscribe(
                config,
                Arc::new(move |event| {
                    let tx = tx.clone();
                    Box::pin(async move {
                        tx.send(event)
                            .map_err(|e| EventError::HandlerError(e.to_string()))
                    })
                }),
            )
            .await
            .expect("Failed to subscribe");

        // Small delay to ensure consumer group is joined
        tokio::time::sleep(Duration::from_secs(2)).await;

        let payload = json!({
            "key_id": "key-1",
            "kid": "kid-1",
            "key_type": "EC",
            "key_attestation": null,
        });

        let event = Event::new(EventType::new(EventType::KEY_CREATED), payload)
            .with_metadata("wallet_id", "wallet-2")
            .with_metadata("correlation_id", "corr-2")
            .with_metadata("category", "key.operations");

        // We use send_sync directly to the specific topic to test subscription
        {
            let payload = serde_json::to_vec(&event).expect("Failed to serialize event");
            let mut p = publisher
                .producer
                .lock()
                .expect("Failed to acquire producer lock");
            KafkaPublisher::send_sync(&mut p, &topic, "wallet-2", &payload)
                .expect("Failed to send message");
        }

        let received = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("Timeout waiting for event")
            .expect("Stream closed");

        assert_eq!(received.id, event.id);
        assert_eq!(received.event_type.as_str(), event.event_type.as_str());
    }

    #[tokio::test]
    async fn test_multi_subscriber_isolation() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let topic = format!("test.multi.{}", uuid::Uuid::new_v4());
        let publisher = KafkaPublisher::new(KafkaPublisherConfig::default())
            .expect("Failed to create publisher");
        let consumer = KafkaConsumer::new(KafkaConsumerConfig::default());

        let (tx1, mut rx1) = tokio::sync::mpsc::unbounded_channel();
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();

        let config = SubscriptionConfig {
            topics: vec![topic.clone()],
        };

        consumer
            .subscribe(
                config.clone(),
                Arc::new(move |event| {
                    let tx = tx1.clone();
                    Box::pin(async move {
                        tx.send(event)
                            .map_err(|e| EventError::HandlerError(e.to_string()))
                    })
                }),
            )
            .await
            .expect("Failed to subscribe stream1");

        consumer
            .subscribe(
                config,
                Arc::new(move |event| {
                    let tx = tx2.clone();
                    Box::pin(async move {
                        tx.send(event)
                            .map_err(|e| EventError::HandlerError(e.to_string()))
                    })
                }),
            )
            .await
            .expect("Failed to subscribe stream2");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let payload = json!({
            "key_id": "key-2",
            "kid": "kid-2",
            "revocation_reason": "compromised",
        });

        let event = Event::new(EventType::new(EventType::KEY_REVOKED), payload)
            .with_metadata("wallet_id", "wallet-3")
            .with_metadata("correlation_id", "corr-3")
            .with_metadata("category", "key.operations");

        {
            let payload = serde_json::to_vec(&event).expect("Failed to serialize event");
            let mut p = publisher
                .producer
                .lock()
                .expect("Failed to acquire producer lock");
            KafkaPublisher::send_sync(&mut p, &topic, "wallet-3", &payload)
                .expect("Failed to send message");
        }

        let r1 = tokio::time::timeout(Duration::from_secs(10), rx1.recv())
            .await
            .expect("S1 timeout")
            .expect("S1 stream error");

        let r2 = tokio::time::timeout(Duration::from_secs(10), rx2.recv())
            .await
            .expect("S2 timeout")
            .expect("S2 stream error");

        assert_eq!(r1.id, event.id);
        assert_eq!(r2.id, event.id);
    }

    #[tokio::test]
    async fn test_custom_event_agnostic() {
        if !wait_for_kafka().await {
            println!("Skipping Kafka integration test");
            return;
        }

        let p_config = KafkaPublisherConfig {
            topic_prefix: "test".to_string(),
            ..Default::default()
        };
        let c_config = KafkaConsumerConfig::default();
        let publisher = KafkaPublisher::new(p_config).expect("Failed to create publisher");
        let consumer = KafkaConsumer::new(c_config);

        let topic = "test.custom.category";
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let s_config = SubscriptionConfig {
            topics: vec![topic.to_string()],
        };
        consumer
            .subscribe(
                s_config,
                Arc::new(move |event| {
                    let tx = tx.clone();
                    Box::pin(async move {
                        tx.send(event)
                            .map_err(|e| EventError::HandlerError(e.to_string()))
                    })
                }),
            )
            .await
            .expect("Failed to subscribe");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let event = Event::new(
            EventType::new("CustomEvent"),
            serde_json::to_value("hello").expect("Failed to serialize"),
        )
        .with_metadata("cid", "corr-custom");

        publisher
            .publish(&event)
            .await
            .expect("Should publish custom event");

        let received = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("S1 timeout")
            .expect("Stream closed");

        assert_eq!(
            received.metadata.get("cid").unwrap().as_str().unwrap(),
            "corr-custom"
        );
        assert_eq!(received.payload.as_str().unwrap(), "hello");
    }
}
