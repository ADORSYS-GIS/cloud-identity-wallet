# wallet-events

[![CI](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml)
[![GitHub](https://img.shields.io/badge/repo-cloud--identity--wallet-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![Rust](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![license](https://shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

An **async event bus** for the [cloud-identity-wallet](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
project, built on top of Apache Kafka.

The crate provides:

- A generic [`Event`] model with typed payloads and extensible metadata.
- [`Publisher`] and [`Consumer`] traits that decouple business logic from the
  underlying message broker.
- Kafka-backed [`KafkaPublisher`] and [`KafkaConsumer`] implementations.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
wallet-events = { path = "../cloud-wallet-events" }
```

### Publish an event

```rust,no_run
use wallet_events::bus::kafka::{KafkaPublisher, KafkaPublisherConfig, ProducerAcks};
use wallet_events::{Publisher, Event, EventType};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let publisher = KafkaPublisher::new(KafkaPublisherConfig {
        bootstrap_servers: "localhost:9092".into(),
        topic_prefix: "wallet".into(),
        producer_acks: ProducerAcks::One,
        ack_timeout_secs: 5,
    })?;

    let event = Event::new(
        EventType::new(EventType::KEY_CREATED),
        json!({ "key_id": "abc-123", "algorithm": "Ed25519" }),
    )
    .with_metadata("wallet_id", "wallet-42")
    .with_metadata("correlation_id", "req-001");

    publisher.publish(&event).await?;
    Ok(())
}
```

### Consume events

```rust,no_run
use wallet_events::bus::kafka::{KafkaConsumer, KafkaConsumerConfig};
use wallet_events::{Consumer, SubscriptionConfig, EventHandler};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let consumer = KafkaConsumer::new(KafkaConsumerConfig {
        bootstrap_servers: "localhost:9092".into(),
        consumer_group_id: "key-service".into(),
    });

    let handler: EventHandler = Arc::new(|event| Box::pin(async move {
        println!(
            "[{}] received event '{}' (wallet: {})",
            event.timestamp,
            event.event_type.as_str(),
            event.metadata.get("wallet_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
        );
        Ok(())
    }));

    consumer
        .subscribe(
            SubscriptionConfig {
                topics: vec!["wallet.key".into(), "wallet.credential".into()],
            },
            handler,
        )
        .await?;

    // Keep the process alive while the consumer runs in the background
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

## Architecture

```text
┌──────────────────────────────────────────────────────┐
│                  Application Layer                   │
│                                                      │
│   impl Publisher ──► KafkaPublisher                  │
│   impl Consumer  ──► KafkaConsumer                   │
│                                                      │
│   (swap with in-memory mocks during unit testing)    │
└──────────────────────────────────────────────────────┘
            │ publishes / subscribes
            ▼
┌──────────────────────────────────────────────────────┐
│                    Apache Kafka                       │
│                                                      │
│  topic: "{prefix}.credential"  (credential events)   │
│  topic: "{prefix}.key"         (key-management)      │
│  topic: "{prefix}.{category}"  (custom categories)   │
└──────────────────────────────────────────────────────┘
```

## Topic Naming

Topics are derived automatically from the `topic_prefix` and the event type:

| Event type | topic_prefix | Resolved topic |
| --- | --- | --- |
| `credential.stored` | `wallet` | `wallet.credential` |
| `key.created` | `wallet` | `wallet.key` |
| _(custom category via metadata)_ | `wallet` | `wallet.<category>` |

Set the `"category"` key in [`Event::with_metadata`] to override the
automatically derived category.

## Well-known Event Types

| Constant | Value | Description |
| --- | --- | --- |
| `EventType::CREDENTIAL_STORED` | `"credential.stored"` | A credential was stored in the wallet |
| `EventType::CREDENTIAL_DELETED` | `"credential.deleted"` | A credential was deleted from the wallet |
| `EventType::PRESENTATION_SUBMITTED` | `"presentation.submitted"` | A verifiable presentation was submitted |
| `EventType::KEY_CREATED` | `"key.created"` | A new cryptographic key was generated |
| `EventType::KEY_ROTATED` | `"key.rotated"` | An existing key was rotated |
| `EventType::KEY_REVOKED` | `"key.revoked"` | A key was revoked |

## Testing with Mocks

Because `Publisher` and `Consumer` are plain traits, you can replace Kafka
with an in-memory implementation in unit tests — no broker required.

```rust
use wallet_events::{Publisher, Consumer, Event, EventType, EventError,
                    SubscriptionConfig, EventHandler};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use serde_json::json;

struct MockPublisher(Arc<Mutex<Vec<Event>>>);

#[async_trait]
impl Publisher for MockPublisher {
    async fn publish(&self, event: &Event) -> Result<(), EventError> {
        self.0.lock().push(event.clone());
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let store = Arc::new(Mutex::new(Vec::new()));
    let publisher = MockPublisher(store.clone());

    let event = Event::new(
        EventType::new(EventType::KEY_CREATED),
        json!({ "key_id": "test-key" }),
    );

    publisher.publish(&event).await.unwrap();
    assert_eq!(store.lock().len(), 1);
}
```

## Error Handling

All operations return `Result<_, EventError>`. The variants map to distinct
failure modes:

| Variant | When it occurs |
| --- | --- |
| `PublishError` | Broker rejected the record or network write failed |
| `SubscribeError` | Consumer failed to register with the broker |
| `SerializationError` | JSON encode/decode of an event failed |
| `ConnectionError` | Transport-level error polling the broker |
| `ConfigurationError` | Producer/consumer creation failed (bad config) |
| `HandlerError` | The user-supplied `EventHandler` returned an error |

## License

Licensed under either of

- [Apache License 2.0](../../LICENSE-APACHE)
- [MIT license](../../LICENSE-MIT)

at your option.
