use async_trait::async_trait;
use cloud_identity_wallet::domain::events::{CredentialIssuedEvent, EventMetadata, WalletEvent};
use cloud_identity_wallet::domain::ports::{EventError, EventHandler, EventPublisher, EventType};
use cloud_identity_wallet::infrastructure::event_bus::{KafkaEventBus, KafkaEventBusConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

struct MockHandler {
    name: String,
    tx: mpsc::UnboundedSender<WalletEvent>,
    fail: bool,
}

#[async_trait]
impl EventHandler for MockHandler {
    fn event_types(&self) -> Vec<EventType> {
        vec![EventType::CredentialIssued]
    }

    async fn handle(&self, event: &WalletEvent) -> Result<(), EventError> {
        if self.fail {
            return Err(EventError::HandlerError("Forced failure".to_string()));
        }
        self.tx.send(event.clone()).unwrap();
        Ok(())
    }

    fn name(&self) -> &'static str {
        leak_str(self.name.clone())
    }
}

fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

async fn wait_for_kafka() -> bool {
    use tokio::net::TcpStream;
    let addr = "localhost:9092";
    for _ in 0..5 {
        if TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

#[tokio::test]
async fn test_event_bus_publish_subscribe() {
    if !wait_for_kafka().await {
        println!("Skipping test: Kafka not available");
        return;
    }

    let config = KafkaEventBusConfig {
        consumer_group_id: format!("test-group-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let bus = KafkaEventBus::new(config).unwrap();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let handler = Arc::new(MockHandler {
        name: "TestHandler".to_string(),
        tx,
        fail: false,
    });

    bus.register_handler(handler).await;
    bus.start_consuming().await.unwrap();

    // Small delay to ensure consumer group is joined
    tokio::time::sleep(Duration::from_secs(2)).await;

    let event = WalletEvent::CredentialIssued(CredentialIssuedEvent {
        metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
        credential: "test-vc".to_string(),
        credential_type: "TestType".to_string(),
        notification_id: None,
        transaction_id: None,
    });

    bus.publish(event.clone()).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("Timeout waiting for event")
        .expect("Stream closed");

    assert_eq!(received, event);
}

#[tokio::test]
async fn test_event_bus_batch_publish() {
    if !wait_for_kafka().await {
        println!("Skipping test: Kafka not available");
        return;
    }

    let config = KafkaEventBusConfig {
        consumer_group_id: format!("test-group-batch-{}", uuid::Uuid::new_v4()),
        transactional_id: Some(format!("test-tx-{}", uuid::Uuid::new_v4())),
        ..Default::default()
    };
    let bus = KafkaEventBus::new(config).unwrap();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let handler = Arc::new(MockHandler {
        name: "BatchHandler".to_string(),
        tx,
        fail: false,
    });

    bus.register_handler(handler).await;
    bus.start_consuming().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let events = vec![
        WalletEvent::CredentialIssued(CredentialIssuedEvent {
            metadata: EventMetadata::new("corr-1".to_string(), "wallet-1".to_string()),
            credential: "vc-1".to_string(),
            credential_type: "Type1".to_string(),
            notification_id: None,
            transaction_id: None,
        }),
        WalletEvent::CredentialIssued(CredentialIssuedEvent {
            metadata: EventMetadata::new("corr-2".to_string(), "wallet-1".to_string()),
            credential: "vc-2".to_string(),
            credential_type: "Type1".to_string(),
            notification_id: None,
            transaction_id: None,
        }),
    ];

    bus.publish_batch(events.clone()).await.unwrap();

    for i in 0..2 {
        let received = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect(&format!("Timeout waiting for event {}", i))
            .expect("Stream closed");
        assert_eq!(received, events[i]);
    }
}

#[tokio::test]
async fn test_event_bus_concurrent_handlers() {
    if !wait_for_kafka().await {
        println!("Skipping test: Kafka not available");
        return;
    }

    let config = KafkaEventBusConfig {
        consumer_group_id: format!("test-group-concurrent-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let bus = KafkaEventBus::new(config).unwrap();

    let (tx1, mut rx1) = mpsc::unbounded_channel();
    let (tx2, mut rx2) = mpsc::unbounded_channel();

    bus.register_handler(Arc::new(MockHandler {
        name: "Handler1".to_string(),
        tx: tx1,
        fail: false,
    }))
    .await;

    bus.register_handler(Arc::new(MockHandler {
        name: "Handler2".to_string(),
        tx: tx2,
        fail: false,
    }))
    .await;

    bus.start_consuming().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let event = WalletEvent::CredentialIssued(CredentialIssuedEvent {
        metadata: EventMetadata::new(
            "corr-concurrent".to_string(),
            "wallet-concurrent".to_string(),
        ),
        credential: "vc-concurrent".to_string(),
        credential_type: "Type".to_string(),
        notification_id: None,
        transaction_id: None,
    });

    bus.publish(event.clone()).await.unwrap();

    let r1 = tokio::time::timeout(Duration::from_secs(5), rx1.recv())
        .await
        .unwrap()
        .unwrap();
    let r2 = tokio::time::timeout(Duration::from_secs(5), rx2.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(r1, event);
    assert_eq!(r2, event);
}

#[tokio::test]
async fn test_event_bus_handler_error_propagation() {
    if !wait_for_kafka().await {
        println!("Skipping test: Kafka not available");
        return;
    }

    let config = KafkaEventBusConfig {
        consumer_group_id: format!("test-group-error-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let bus = KafkaEventBus::new(config).unwrap();

    let (tx_success, mut rx_success) = mpsc::unbounded_channel();

    // Handler that fails
    bus.register_handler(Arc::new(MockHandler {
        name: "FailingHandler".to_string(),
        tx: mpsc::unbounded_channel().0, // Unused
        fail: true,
    }))
    .await;

    // Handler that succeeds
    bus.register_handler(Arc::new(MockHandler {
        name: "SuccessHandler".to_string(),
        tx: tx_success,
        fail: false,
    }))
    .await;

    bus.start_consuming().await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    let event = WalletEvent::CredentialIssued(CredentialIssuedEvent {
        metadata: EventMetadata::new("corr-error".to_string(), "wallet-error".to_string()),
        credential: "vc-error".to_string(),
        credential_type: "Type".to_string(),
        notification_id: None,
        transaction_id: None,
    });

    bus.publish(event.clone()).await.unwrap();

    // The successful handler should still receive the event even if the other one failed
    let received = tokio::time::timeout(Duration::from_secs(5), rx_success.recv())
        .await
        .expect("Timeout waiting for event in success handler")
        .expect("Stream closed");

    assert_eq!(received, event);
}
