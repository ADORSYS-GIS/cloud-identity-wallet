use crate::domain::events::WalletEvent;
use crate::domain::ports::{EventError, EventHandler, EventType};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, warn};

/// Security monitoring handler that detects suspicious patterns
pub struct SecurityMonitoringHandler {
    // Track failed proof attempts by wallet_id
    failed_proofs: Arc<RwLock<HashMap<String, u32>>>,
    // Track nonce usage to detect replay attacks
    used_nonces: Arc<RwLock<HashMap<String, bool>>>,
    max_failed_proofs: u32,
}

impl SecurityMonitoringHandler {
    pub fn new(max_failed_proofs: u32) -> Self {
        Self {
            failed_proofs: Arc::new(RwLock::new(HashMap::new())),
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            max_failed_proofs,
        }
    }

    async fn check_presentation_verification(&self, event: &WalletEvent) -> Result<(), EventError> {
        if let WalletEvent::PresentationVerified(e) = event {
            match &e.validation_status {
                crate::domain::events::ValidationStatus::Invalid { reason } => {
                    warn!(
                        wallet_id = %e.metadata.wallet_id,
                        request_id = %e.request_id,
                        reason = %reason,
                        "Invalid presentation detected"
                    );

                    // Track failed attempts
                    let mut failed = self.failed_proofs.write().await;
                    let count = failed.entry(e.metadata.wallet_id.clone()).or_insert(0);
                    *count += 1;

                    if *count >= self.max_failed_proofs {
                        error!(
                            wallet_id = %e.metadata.wallet_id,
                            failed_attempts = %count,
                            "SECURITY ALERT: Multiple failed presentation attempts"
                        );
                    }
                }
                crate::domain::events::ValidationStatus::Valid => {
                    // Reset failed attempts on success
                    let mut failed = self.failed_proofs.write().await;
                    failed.remove(&e.metadata.wallet_id);
                }
            }
        }

        Ok(())
    }

    async fn check_nonce_reuse(&self, event: &WalletEvent) -> Result<(), EventError> {
        let nonce = match event {
            WalletEvent::PresentationRequestReceived(e) => Some(&e.nonce),
            WalletEvent::PresentationRequestSent(e) => Some(&e.nonce),
            _ => None,
        };

        if let Some(nonce_value) = nonce {
            let mut nonces = self.used_nonces.write().await;
            if nonces.contains_key(nonce_value) {
                error!(
                    nonce = %nonce_value,
                    "SECURITY ALERT: Nonce reuse detected - potential replay attack"
                );
                return Err(EventError::HandlerError("Nonce reuse detected".to_string()));
            }
            nonces.insert(nonce_value.clone(), true);
        }

        Ok(())
    }

    /// Get failed proof count for a wallet
    pub async fn failed_proof_count(&self, wallet_id: &str) -> u32 {
        let failed = self.failed_proofs.read().await;
        failed.get(wallet_id).copied().unwrap_or(0)
    }
}

impl Default for SecurityMonitoringHandler {
    fn default() -> Self {
        Self::new(5)
    }
}

#[async_trait]
impl EventHandler for SecurityMonitoringHandler {
    fn event_types(&self) -> Vec<EventType> {
        vec![
            EventType::PresentationRequestSent,
            EventType::PresentationRequestReceived,
            EventType::PresentationVerified,
        ]
    }

    async fn handle(&self, event: &WalletEvent) -> Result<(), EventError> {
        self.check_nonce_reuse(event).await?;
        self.check_presentation_verification(event).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "SecurityMonitoringHandler"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::{
        EventMetadata, PresentationRequestReceivedEvent, PresentationVerifiedEvent,
        ValidationStatus,
    };

    #[tokio::test]
    async fn test_security_handler_detects_nonce_reuse() {
        let handler = SecurityMonitoringHandler::new(5);

        let event1 = WalletEvent::PresentationRequestReceived(PresentationRequestReceivedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            request_id: "req-123".to_string(),
            dcql_query: "{}".to_string(),
            nonce: "nonce-123".to_string(),
            client_id: "client-1".to_string(),
            response_uri: None,
        });

        // First use should succeed
        assert!(handler.handle(&event1).await.is_ok());

        // Second use should fail
        assert!(handler.handle(&event1).await.is_err());
    }

    #[tokio::test]
    async fn test_security_handler_tracks_failed_proofs() {
        let handler = SecurityMonitoringHandler::new(3);

        let event = WalletEvent::PresentationVerified(PresentationVerifiedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            request_id: "req-123".to_string(),
            presentation_submission_id: "sub-456".to_string(),
            validation_status: ValidationStatus::Invalid {
                reason: "Invalid signature".to_string(),
            },
            holder_binding_verified: false,
        });

        handler.handle(&event).await.unwrap();
        handler.handle(&event).await.unwrap();

        assert_eq!(handler.failed_proof_count("wallet-456").await, 2);
    }

    #[tokio::test]
    async fn test_security_handler_resets_on_success() {
        let handler = SecurityMonitoringHandler::new(3);

        let failed_event = WalletEvent::PresentationVerified(PresentationVerifiedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            request_id: "req-123".to_string(),
            presentation_submission_id: "sub-456".to_string(),
            validation_status: ValidationStatus::Invalid {
                reason: "Invalid signature".to_string(),
            },
            holder_binding_verified: false,
        });

        let success_event = WalletEvent::PresentationVerified(PresentationVerifiedEvent {
            metadata: EventMetadata::new("corr-124".to_string(), "wallet-456".to_string()),
            request_id: "req-124".to_string(),
            presentation_submission_id: "sub-457".to_string(),
            validation_status: ValidationStatus::Valid,
            holder_binding_verified: true,
        });

        handler.handle(&failed_event).await.unwrap();
        assert_eq!(handler.failed_proof_count("wallet-456").await, 1);

        handler.handle(&success_event).await.unwrap();
        assert_eq!(handler.failed_proof_count("wallet-456").await, 0);
    }
}
