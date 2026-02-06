/*
   This module specifies the API by which external modules interact with the wallet domain.
*/

use crate::domain::events::WalletEvent;
use async_trait::async_trait;
use std::pin::Pin;
use tokio_stream::Stream;

/// Error type for event operations
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Failed to publish event: {0}")]
    PublishError(String),

    #[error("Failed to subscribe to events: {0}")]
    SubscribeError(String),

    #[error("Failed to handle event: {0}")]
    HandlerError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Type alias for event stream
pub type EventStream = Pin<Box<dyn Stream<Item = Result<WalletEvent, EventError>> + Send>>;

/// Event type discriminator for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    CredentialOfferSent,
    CredentialOfferReceived,
    CredentialIssued,
    CredentialAcknowledged,
    CredentialStored,
    CredentialDeleted,
    PresentationRequestSent,
    PresentationRequestReceived,
    PresentationSubmitted,
    PresentationVerified,
    KeyCreated,
    KeyRotated,
    KeyRevoked,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::CredentialOfferSent => "CredentialOfferSent",
            EventType::CredentialOfferReceived => "CredentialOfferReceived",
            EventType::CredentialIssued => "CredentialIssued",
            EventType::CredentialAcknowledged => "CredentialAcknowledged",
            EventType::CredentialStored => "CredentialStored",
            EventType::CredentialDeleted => "CredentialDeleted",
            EventType::PresentationRequestSent => "PresentationRequestSent",
            EventType::PresentationRequestReceived => "PresentationRequestReceived",
            EventType::PresentationSubmitted => "PresentationSubmitted",
            EventType::PresentationVerified => "PresentationVerified",
            EventType::KeyCreated => "KeyCreated",
            EventType::KeyRotated => "KeyRotated",
            EventType::KeyRevoked => "KeyRevoked",
        }
    }
}

/// Trait for publishing events to the event bus
#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: WalletEvent) -> Result<(), EventError>;
    async fn publish_batch(&self, events: Vec<WalletEvent>) -> Result<(), EventError>;
}

/// Trait for subscribing to events from the event bus
#[async_trait]
pub trait EventSubscriber: Send + Sync {
    async fn subscribe(&self, event_types: Vec<EventType>) -> Result<EventStream, EventError>;
    async fn subscribe_all(&self) -> Result<EventStream, EventError>;
}

/// Trait for handling events
#[async_trait]
pub trait EventHandler: Send + Sync {
    fn event_types(&self) -> Vec<EventType>;
    async fn handle(&self, event: &WalletEvent) -> Result<(), EventError>;
    fn name(&self) -> &'static str {
        "UnnamedHandler"
    }
}
