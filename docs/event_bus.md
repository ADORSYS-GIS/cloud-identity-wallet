# Event Schema and Event Bus Implementation

## Overview

This implementation provides a comprehensive event-driven architecture for wallet operations using **Apache Kafka** as the event bus. The system captures all wallet operations (credential issuance, presentations, key management) as structured events for audit, monitoring, and integration purposes.

## Architecture

### Components

1. **Event Schemas** (`src/domain/events.rs`)
   - Comprehensive event types for all wallet operations
   - Structured metadata (event_id, timestamp, correlation_id, wallet_id, schema_version)
   - Full serialization/deserialization support

2. **Event Bus Ports** (`src/domain/ports.rs`)
   - `EventPublisher` - Interface for publishing events
   - `EventSubscriber` - Interface for subscribing to events
   - `EventHandler` - Interface for handling events

3. **Kafka Event Bus** (`src/infrastructure/event_bus.rs`)
   - Production-ready Kafka integration using `rdkafka`
   - Topic-based routing by event category
   - Partitioning by `wallet_id` for ordering guarantees
   - Dead letter queue for failed events
   - Graceful shutdown and offset management

4. **Event Handlers** (`src/infrastructure/handlers/`)
   - **AuditLogHandler** - Logs all events for compliance
   - **MetricsHandler** - Tracks event counts and statistics
   - **NotificationHandler** - Sends acknowledgments to issuers
   - **SecurityMonitoringHandler** - Detects suspicious patterns

## Event Types

### Credential Offer Events
- `CredentialOfferSent` - Issuer sends credential offer
- `CredentialOfferReceived` - Wallet receives credential offer

### Credential Issuance Events
- `CredentialIssued` - Credential issued by issuer
- `CredentialAcknowledged` - Wallet acknowledges receipt

### Credential Storage Events
- `CredentialStored` - Credential stored in wallet
- `CredentialDeleted` - Credential deleted from wallet

### Presentation Events
- `PresentationRequestSent` - Verifier sends presentation request
- `PresentationRequestReceived` - Wallet receives presentation request
- `PresentationSubmitted` - Wallet submits presentation
- `PresentationVerified` - Verifier verifies presentation

### Key Operation Events
- `KeyCreated` - New key generated
- `KeyRotated` - Key rotated
- `KeyRevoked` - Key revoked

## Kafka Topic Structure

Events are routed to topics based on their category:

- `wallet.credential.offers` - Credential offer events
- `wallet.credential.issuance` - Credential issuance events
- `wallet.credential.storage` - Credential storage events
- `wallet.presentation.requests` - Presentation request events
- `wallet.presentation.submissions` - Presentation submission events
- `wallet.key.operations` - Key lifecycle events
- `wallet.dlq` - Dead letter queue for failed events

## Getting Started

### Prerequisites

- Rust toolchain (stable)
- Docker and Docker Compose (for local Kafka)

### 1. Start Kafka Cluster

```bash
# Start Kafka, Zookeeper, and Kafka UI
docker-compose up -d

# Verify Kafka is running
docker-compose logs -f kafka

# Access Kafka UI at http://localhost:8080
```

### 2. Build the Project

```bash
cargo build
```

### 3. Run Tests

```bash
# Run unit tests
cargo test --lib

# Run integration tests (requires Kafka running)
cargo test --test integration_tests -- --ignored
```

## Usage Examples

### Publishing Events

```rust
use cloud_identity_wallet::domain::events::*;
use cloud_identity_wallet::domain::ports::EventPublisher;
use cloud_identity_wallet::infrastructure::event_bus::{KafkaEventBus, KafkaEventBusConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create event bus
    let config = KafkaEventBusConfig::default();
    let event_bus = KafkaEventBus::new(config)?;

    // Create and publish an event
    let event = WalletEvent::CredentialOfferReceived(CredentialOfferReceivedEvent {
        metadata: EventMetadata::new(
            "correlation-123".to_string(),
            "wallet-456".to_string(),
        ),
        offer_id: "offer-789".to_string(),
        credential_issuer: "https://issuer.example.com".to_string(),
        credential_configuration_ids: vec!["UniversityDegree".to_string()],
        grants: None,
        credential_offer_uri: None,
    });

    event_bus.publish(event).await?;

    Ok(())
}
```

### Subscribing to Events

```rust
use cloud_identity_wallet::domain::ports::{EventSubscriber, EventType};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = KafkaEventBusConfig::default();
    let event_bus = KafkaEventBus::new(config)?;

    // Subscribe to specific event types
    let mut stream = event_bus.subscribe(vec![
        EventType::CredentialIssued,
        EventType::CredentialStored,
    ]).await?;

    // Process events
    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(event) => {
                println!("Received event: {}", event.event_type_name());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}
```

### Registering Event Handlers

```rust
use std::sync::Arc;
use cloud_identity_wallet::infrastructure::handlers::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = KafkaEventBusConfig::default();
    let event_bus = KafkaEventBus::new(config)?;

    // Register handlers
    event_bus.register_handler(Arc::new(AuditLogHandler::new())).await;
    event_bus.register_handler(Arc::new(MetricsHandler::new())).await;
    event_bus.register_handler(Arc::new(SecurityMonitoringHandler::new(5))).await;

    // Start consuming and dispatching to handlers
    event_bus.start_consuming().await?;

    // Keep application running
    tokio::signal::ctrl_c().await?;

    Ok(())
}
```

## Configuration

Configure the event bus via `KafkaEventBusConfig`:

```rust
let config = KafkaEventBusConfig {
    bootstrap_servers: "localhost:9092".to_string(),
    topic_prefix: "wallet".to_string(),
    consumer_group_id: "wallet-event-handlers".to_string(),
    producer_acks: "all".to_string(),
    producer_retries: 3,
    enable_dlq: true,
    dlq_topic: "wallet.dlq".to_string(),
};
```

## Event Correlation

All events include a `correlation_id` to link related events across flows:

```rust
let correlation_id = "flow-123".to_string();

// All events in this flow use the same correlation_id
let offer_event = WalletEvent::CredentialOfferReceived(...);
let issued_event = WalletEvent::CredentialIssued(...);
let stored_event = WalletEvent::CredentialStored(...);
```

## Monitoring

### Kafka UI

Access the Kafka UI at `http://localhost:8080` to:
- View topics and partitions
- Monitor consumer lag
- Inspect messages
- View consumer groups

### Metrics Handler

The `MetricsHandler` tracks:
- Total event count
- Event count by type
- Processing latency (future enhancement)

```rust
let metrics = Arc::new(MetricsHandler::new());
event_bus.register_handler(metrics.clone()).await;

// Later, query metrics
let total = metrics.total_events();
let issued_count = metrics.event_count_by_type("CredentialIssued").await;
```

## Security Monitoring

The `SecurityMonitoringHandler` detects:
- Nonce reuse (potential replay attacks)
- Multiple failed presentation verifications
- Suspicious patterns

## Production Considerations

1. **Kafka Cluster**: Use a production Kafka cluster with:
   - Multiple brokers (replication factor ≥ 3)
   - Proper authentication (SASL/SCRAM or mTLS)
   - TLS encryption for data in transit

2. **Topic Configuration**:
   - Appropriate retention policies
   - Sufficient partitions for parallelism
   - Replication for durability

3. **Consumer Groups**:
   - Use unique consumer group IDs for different applications
   - Monitor consumer lag

4. **Error Handling**:
   - Monitor dead letter queue
   - Implement retry logic for transient failures
   - Alert on persistent errors

## Testing

### Unit Tests

```bash
cargo test --lib
```

Tests cover:
- Event serialization/deserialization
- Event bus configuration
- Handler logic
- Topic routing

### Integration Tests

```bash
# Start Kafka first
docker-compose up -d

# Run integration tests
cargo test --test integration_tests -- --ignored
```

Integration tests cover:
- End-to-end credential issuance flow
- End-to-end presentation flow
- Key operation events
- Event correlation
- Security monitoring

## Troubleshooting

### Kafka Connection Issues

```
Error: Failed to create producer: ...
```

**Solution**: Ensure Kafka is running:
```bash
docker-compose ps
docker-compose logs kafka
```

### Consumer Lag

If consumers are falling behind:
1. Check consumer group lag in Kafka UI
2. Increase number of partitions
3. Scale consumer instances
4. Optimize handler processing

### Dead Letter Queue

Monitor the DLQ topic for failed events:
```bash
# View DLQ messages in Kafka UI
# Topic: wallet.dlq
```

## Future Enhancements

1. **Schema Registry**: Integrate Confluent Schema Registry for Avro schemas
2. **Transactions**: Use Kafka transactions for atomic multi-event operations
3. **Metrics**: Add Prometheus metrics export
4. **Tracing**: Add distributed tracing with OpenTelemetry
5. **Compaction**: Use log compaction for state topics
6. **SASL/SSL**: Add production authentication and encryption

## References

- [OpenID4VCI Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [Apache Kafka Documentation](https://kafka.apache.org/documentation/)
- [rdkafka Rust Client](https://docs.rs/rdkafka/)
