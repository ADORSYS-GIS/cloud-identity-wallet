use crate::domain::events::WalletEvent;
use crate::domain::ports::{EventError, EventHandler, EventType};
use async_trait::async_trait;
use tracing::info;

/// Audit log handler that logs all events for compliance and debugging
pub struct AuditLogHandler;

impl AuditLogHandler {
    pub fn new() -> Self {
        Self
    }

    fn is_security_relevant(&self, event: &WalletEvent) -> bool {
        matches!(
            event,
            WalletEvent::CredentialDeleted(_)
                | WalletEvent::KeyCreated(_)
                | WalletEvent::KeyRotated(_)
                | WalletEvent::KeyRevoked(_)
        )
    }
}

impl Default for AuditLogHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventHandler for AuditLogHandler {
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
        let metadata = event.metadata();
        let is_security = self.is_security_relevant(event);

        // Log with structured fields for audit trail
        if is_security {
            info!(
                event_id = %metadata.event_id,
                event_type = event.event_type_name(),
                correlation_id = %metadata.correlation_id,
                wallet_id = %metadata.wallet_id,
                timestamp = %metadata.timestamp,
                security_relevant = true,
                "AUDIT: Security-relevant event"
            );
        } else {
            info!(
                event_id = %metadata.event_id,
                event_type = event.event_type_name(),
                correlation_id = %metadata.correlation_id,
                wallet_id = %metadata.wallet_id,
                timestamp = %metadata.timestamp,
                "AUDIT: Wallet event"
            );
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "AuditLogHandler"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::{CredentialDeletedEvent, EventMetadata, KeyCreatedEvent};

    #[tokio::test]
    async fn test_audit_log_handler_handles_all_events() {
        let handler = AuditLogHandler::new();
        let event_types = handler.event_types();
        assert_eq!(event_types.len(), 13);
    }

    #[tokio::test]
    async fn test_audit_log_handler_security_relevant() {
        let handler = AuditLogHandler::new();

        let event = WalletEvent::KeyCreated(KeyCreatedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            key_id: "key-123".to_string(),
            kid: "did:example:123#key-1".to_string(),
            key_type: "Ed25519".to_string(),
            key_attestation: None,
        });

        assert!(handler.is_security_relevant(&event));
        assert!(handler.handle(&event).await.is_ok());
    }

    #[tokio::test]
    async fn test_audit_log_handler_credential_deleted() {
        let handler = AuditLogHandler::new();

        let event = WalletEvent::CredentialDeleted(CredentialDeletedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            credential_id: "cred-123".to_string(),
            notification_id: "notif-456".to_string(),
            event: "credential_deleted".to_string(),
        });

        assert!(handler.is_security_relevant(&event));
        assert!(handler.handle(&event).await.is_ok());
    }
}
