use crate::domain::events::WalletEvent;
use crate::domain::ports::{EventError, EventHandler, EventType};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Metrics handler that tracks event counts and latency.
pub struct MetricsHandler {
    event_counts: HashMap<EventType, AtomicU64>,
    total_events: AtomicU64,
}

impl MetricsHandler {
    pub fn new() -> Self {
        let mut event_counts = HashMap::new();

        // Pre-initialize with all known event types to prevent unbounded growth
        let all_types = [
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
        ];

        for &event_type in &all_types {
            event_counts.insert(event_type, AtomicU64::new(0));
        }

        Self {
            event_counts,
            total_events: AtomicU64::new(0),
        }
    }

    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Get event count by type name (string lookup for backward compatibility)
    pub fn event_count_by_type(&self, event_type: &str) -> u64 {
        self.event_counts
            .iter()
            .find(|(k, _)| k.as_str() == event_type)
            .map(|(_, v)| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get all event counts as a HashMap<String, u64>
    pub fn all_event_counts(&self) -> HashMap<String, u64> {
        self.event_counts
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.load(Ordering::Relaxed)))
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
        let event_type = event.event_type();

        // Increment total count
        self.total_events.fetch_add(1, Ordering::Relaxed);

        // Increment event type count (lockless since map is pre-initialized)
        if let Some(counter) = self.event_counts.get(&event_type) {
            counter.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            event_type = %event.event_type_name(),
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
        assert_eq!(handler.event_count_by_type("CredentialIssued"), 2);
        assert_eq!(handler.event_count_by_type("KeyCreated"), 1);
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

        let all_counts = handler.all_event_counts();
        assert_eq!(all_counts.get("CredentialIssued"), Some(&1));
    }
}
