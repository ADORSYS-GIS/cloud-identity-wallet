# wallet-events

[![CI](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml)
[![GitHub](https://img.shields.io/badge/repo-cloud--identity--wallet-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![Rust](https://img.shields.io/badge/msrv-1.85-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![license](https://shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

An async event bus primarily built for the [cloud-identity-wallet](https://github.com/ADORSYS-GIS/cloud-identity-wallet) project.

## Features

- Generic [`Event`] model with typed payloads and extensible metadata
- [`Publisher`] and [`Consumer`] traits decoupling business logic from the message broker
- Built-in implementations for production use

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
wallet-events = { path = "../cloud-wallet-events" }
```

### Publish an event

```rust,no_run
use wallet_events::{Publisher, Event, EventType};
use serde_json::json;

let event = Event::new(
    EventType::new(EventType::KEY_CREATED),
    json!({ "key_id": "abc-123" }),
)
.with_metadata("wallet_id", "wallet-42");

publisher.publish(&event).await?;
```

### Consume events

```rust,no_run
use wallet_events::{Consumer, SubscriptionConfig, EventHandler};
use std::sync::Arc;

let handler: EventHandler = Arc::new(|event| Box::pin(async move {
    println!("Received: {}", event.event_type.as_str());
    Ok(())
}));

consumer.subscribe(SubscriptionConfig::default(), handler).await?;
```

## Well-known Event Types

| Constant                          | Value                    |
|-----------------------------------|--------------------------|
| `EventType::CREDENTIAL_STORED`    | `"credential.stored"`    |
| `EventType::CREDENTIAL_DELETED`   | `"credential.deleted"`   |
| `EventType::PRESENTATION_SUBMITTED` | `"presentation.submitted"` |
| `EventType::KEY_CREATED`          | `"key.created"`          |
| `EventType::KEY_ROTATED`          | `"key.rotated"`          |
| `EventType::KEY_REVOKED`          | `"key.revoked"`          |

## Testing

Implement `Publisher` and `Consumer` traits with in-memory mocks for unit tests—no broker required.

## License

Licensed under either of [Apache License 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
