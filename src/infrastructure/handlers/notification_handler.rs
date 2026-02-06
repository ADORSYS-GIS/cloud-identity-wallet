use crate::domain::events::WalletEvent;
use crate::domain::ports::{EventError, EventHandler, EventType};
use async_trait::async_trait;
use tracing::{info, warn};

/// Notification handler that sends notifications to OpenID4VCI Notification Endpoint
pub struct NotificationHandler {
    notification_endpoint: Option<String>,
    max_retries: u32,
    client: reqwest::Client,
}

impl NotificationHandler {
    pub fn new(notification_endpoint: Option<String>, max_retries: u32) -> Self {
        Self {
            notification_endpoint,
            max_retries,
            client: reqwest::Client::new(),
        }
    }

    async fn send_notification(
        &self,
        notification_id: &str,
        event_type: &str,
    ) -> Result<(), EventError> {
        let endpoint = match &self.notification_endpoint {
            Some(e) => e,
            None => {
                return Ok(());
            }
        };

        info!(
            notification_id = %notification_id,
            event_type = %event_type,
            endpoint = %endpoint,
            "Sending notification to issuer"
        );

        let payload = serde_json::json!({
            "notification_id": notification_id,
            "event": event_type,
        });

        let mut attempts = 0;
        loop {
            match self.client.post(endpoint).json(&payload).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("Notification sent successfully");
                        return Ok(());
                    } else {
                        warn!(
                            status = %response.status(),
                            "Failed to send notification (attempt {}/{})",
                            attempts + 1,
                            self.max_retries
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Network error sending notification (attempt {}/{})",
                        attempts + 1,
                        self.max_retries
                    );
                }
            }

            attempts += 1;
            if attempts > self.max_retries {
                return Err(EventError::HandlerError(format!(
                    "Failed to send notification after {} attempts",
                    self.max_retries
                )));
            }

            tokio::time::sleep(std::time::Duration::from_millis(
                100 * 2_u64.pow(attempts - 1),
            ))
            .await;
        }
    }
}

#[async_trait]
impl EventHandler for NotificationHandler {
    fn event_types(&self) -> Vec<EventType> {
        vec![
            EventType::CredentialAcknowledged,
            EventType::CredentialDeleted,
        ]
    }

    async fn handle(&self, event: &WalletEvent) -> Result<(), EventError> {
        match event {
            WalletEvent::CredentialAcknowledged(e) => {
                self.send_notification(&e.notification_id, &e.event).await?;
            }
            WalletEvent::CredentialDeleted(e) => {
                self.send_notification(&e.notification_id, &e.event).await?;
            }
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "NotificationHandler"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::events::{
        CredentialAcknowledgedEvent, CredentialDeletedEvent, EventMetadata,
    };

    #[tokio::test]
    async fn test_notification_handler_event_types() {
        let handler = NotificationHandler::new(None, 3);
        let event_types = handler.event_types();
        assert_eq!(event_types.len(), 2);
        assert!(event_types.contains(&EventType::CredentialAcknowledged));
        assert!(event_types.contains(&EventType::CredentialDeleted));
    }

    #[tokio::test]
    async fn test_notification_handler_acknowledged() {
        let handler = NotificationHandler::new(
            Some("https://issuer.example.com/notification".to_string()),
            3,
        );

        let event = WalletEvent::CredentialAcknowledged(CredentialAcknowledgedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            notification_id: "notif-123".to_string(),
            event: "credential_accepted".to_string(),
        });

        assert!(handler.handle(&event).await.is_err());
    }

    #[tokio::test]
    async fn test_notification_handler_deleted() {
        let handler = NotificationHandler::new(None, 3);

        let event = WalletEvent::CredentialDeleted(CredentialDeletedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            credential_id: "cred-123".to_string(),
            notification_id: "notif-456".to_string(),
            event: "credential_deleted".to_string(),
        });

        assert!(handler.handle(&event).await.is_ok());
    }
}
