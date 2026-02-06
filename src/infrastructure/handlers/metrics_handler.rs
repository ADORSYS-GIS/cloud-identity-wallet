use crate::domain::events::WalletEvent;
use crate::domain::ports::{EventError, EventHandler, EventType};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::debug;

/// Metrics handler that tracks event counts and latency
pub struct MetricsHandler {
    event_counts: Arc<RwLock<HashMap<String, AtomicU64>>>,
    total_events: Arc<AtomicU64>,
}

impl MetricsHandler {
    pub fn new() -> Self {
        Self {
            event_counts: Arc::new(RwLock::new(HashMap::new())),
            total_events: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    pub async fn event_count_by_type(&self, event_type: &str) -> u64 {
        let counts = self.event_counts.read().await;
        counts
            .get(event_type)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub async fn all_event_counts(&self) -> HashMap<String, u64> {
        let counts = self.event_counts.read().await;
        counts
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect()
    }
}

impl Default for MetricsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventHandler for MetricsHandler {
    fn event_types(&self) -> Vec<EventType> {
        // Subscribe to all event types
        vec![
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
        ]
    }

    async fn handle(&self, event: &WalletEvent) -> Result<(), EventError> {
        let event_type = event.event_type_name().to_string();

        // Increment total count
        self.total_events.fetch_add(1, Ordering::Relaxed);

        // Increment event type count
        let mut counts = self.event_counts.write().await;
        counts
            .entry(event_type.clone())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        debug!(
            event_type = %event_type,
            total_events = self.total_events.load(Ordering::Relaxed),
            "Metrics updated"
        );

        Ok(())
    }

    fn name(&self) -> &'static str {
        "MetricsHandler"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::{CredentialIssuedEvent, EventMetadata, KeyCreatedEvent};

    #[tokio::test]
    async fn test_metrics_handler_counts_events() {
        let handler = MetricsHandler::new();

        let event1 = WalletEvent::CredentialIssued(CredentialIssuedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            credential: "eyJhbGc...".to_string(),
            credential_type: "UniversityDegree".to_string(),
            notification_id: None,
            transaction_id: None,
        });

        let event2 = WalletEvent::KeyCreated(KeyCreatedEvent {
            metadata: EventMetadata::new("corr-124".to_string(), "wallet-456".to_string()),
            key_id: "key-123".to_string(),
            kid: "did:example:123#key-1".to_string(),
            key_type: "Ed25519".to_string(),
            key_attestation: None,
        });

        handler.handle(&event1).await.unwrap();
        handler.handle(&event2).await.unwrap();
        handler.handle(&event1).await.unwrap();

        assert_eq!(handler.total_events(), 3);
        assert_eq!(handler.event_count_by_type("CredentialIssued").await, 2);
        assert_eq!(handler.event_count_by_type("KeyCreated").await, 1);
    }

    #[tokio::test]
    async fn test_metrics_handler_all_counts() {
        let handler = MetricsHandler::new();

        let event = WalletEvent::CredentialIssued(CredentialIssuedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            credential: "eyJhbGc...".to_string(),
            credential_type: "UniversityDegree".to_string(),
            notification_id: None,
            transaction_id: None,
        });

        handler.handle(&event).await.unwrap();

        let all_counts = handler.all_event_counts().await;
        assert_eq!(all_counts.get("CredentialIssued"), Some(&1));
    }
}
