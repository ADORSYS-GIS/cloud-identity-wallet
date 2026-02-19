use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Webhook payload sent to external systems
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookPayload {
    pub event_id: String,

    pub event_type: String,

    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    pub wallet_id: String,

    pub correlation_id: String,

    pub data: Value,

    #[serde(default = "default_schema_version")]
    pub schema_version: String,
}

fn default_schema_version() -> String {
    "1.0.0".to_string()
}

impl WebhookPayload {
    /// Create a new webhook payload
    pub fn new(
        event_id: String,
        event_type: String,
        timestamp: OffsetDateTime,
        wallet_id: String,
        correlation_id: String,
        data: Value,
    ) -> Self {
        Self {
            event_id,
            event_type,
            timestamp,
            wallet_id,
            correlation_id,
            data,
            schema_version: default_schema_version(),
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get event type without namespace (e.g., "credential.stored" -> "stored")
    pub fn event_name(&self) -> &str {
        self.event_type
            .split('.')
            .next_back()
            .unwrap_or(&self.event_type)
    }

    /// Get event namespace (e.g., "credential.stored" -> "credential")
    pub fn event_namespace(&self) -> Option<&str> {
        self.event_type.split('.').next()
    }
}

/// Response expected from webhook endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookResponse {
    pub acknowledged: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_id: Option<String>,
}

impl WebhookResponse {
    /// Create a simple acknowledgment response
    pub fn acknowledged() -> Self {
        Self {
            acknowledged: true,
            message: None,
            processing_id: None,
        }
    }

    /// Create acknowledgment with message
    pub fn with_message(message: String) -> Self {
        Self {
            acknowledged: true,
            message: Some(message),
            processing_id: None,
        }
    }

    /// Create acknowledgment with processing ID
    pub fn with_processing_id(processing_id: String) -> Self {
        Self {
            acknowledged: true,
            message: None,
            processing_id: Some(processing_id),
        }
    }
}

/// Delivery status for tracking webhook attempts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeliveryStatus {
    pub subscription_id: String,

    pub event_id: String,

    pub attempt: u32,

    pub status: DeliveryState,

    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    pub status_code: Option<u16>,

    pub response_time_ms: Option<u64>,

    pub error: Option<String>,

    #[serde(with = "time::serde::rfc3339::option")]
    pub next_retry_at: Option<OffsetDateTime>,
}

impl DeliveryStatus {
    /// Create a pending delivery status
    pub fn pending(subscription_id: String, event_id: String) -> Self {
        Self {
            subscription_id,
            event_id,
            attempt: 0,
            status: DeliveryState::Pending,
            timestamp: OffsetDateTime::now_utc(),
            status_code: None,
            response_time_ms: None,
            error: None,
            next_retry_at: None,
        }
    }

    /// Mark as in progress
    pub fn in_progress(mut self, attempt: u32) -> Self {
        self.status = DeliveryState::InProgress;
        self.attempt = attempt;
        self.timestamp = OffsetDateTime::now_utc();
        self
    }

    /// Mark as succeeded
    pub fn succeeded(mut self, status_code: u16, response_time_ms: u64) -> Self {
        self.status = DeliveryState::Succeeded;
        self.status_code = Some(status_code);
        self.response_time_ms = Some(response_time_ms);
        self.timestamp = OffsetDateTime::now_utc();
        self
    }

    /// Mark as failed
    pub fn failed(
        mut self,
        status_code: Option<u16>,
        error: String,
        next_retry_at: Option<OffsetDateTime>,
    ) -> Self {
        self.status = DeliveryState::Failed;
        self.status_code = status_code;
        self.error = Some(error);
        self.next_retry_at = next_retry_at;
        self.timestamp = OffsetDateTime::now_utc();
        self
    }

    /// Mark as permanently failed (after max retries)
    pub fn permanent_failure(mut self, error: String) -> Self {
        self.status = DeliveryState::PermanentFailure;
        self.error = Some(error);
        self.timestamp = OffsetDateTime::now_utc();
        self.next_retry_at = None;
        self
    }
}

/// State of a webhook delivery
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Pending,

    InProgress,

    Succeeded,

    Failed,

    PermanentFailure,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::Duration;

    #[test]
    fn test_webhook_payload_creation() {
        let payload = WebhookPayload::new(
            "evt-123".to_string(),
            "credential.stored".to_string(),
            OffsetDateTime::now_utc(),
            "wallet-456".to_string(),
            "corr-789".to_string(),
            json!({
                "credential_id": "cred-123",
                "credential_type": "UniversityDegree"
            }),
        );

        assert_eq!(payload.event_id, "evt-123");
        assert_eq!(payload.event_type, "credential.stored");
        assert_eq!(payload.wallet_id, "wallet-456");
        assert_eq!(payload.schema_version, "1.0.0");
    }

    #[test]
    fn test_webhook_payload_serialization() -> Result<(), serde_json::Error> {
        let payload = WebhookPayload::new(
            "evt-123".to_string(),
            "credential.stored".to_string(),
            OffsetDateTime::now_utc(),
            "wallet-456".to_string(),
            "corr-789".to_string(),
            json!({"test": "data"}),
        );

        let json = payload.to_json()?;
        let deserialized: WebhookPayload = serde_json::from_str(&json)?;

        assert_eq!(payload.event_id, deserialized.event_id);
        assert_eq!(payload.event_type, deserialized.event_type);
        Ok(())
    }

    #[test]
    fn test_event_name_extraction() {
        let payload = WebhookPayload::new(
            "evt-123".to_string(),
            "credential.stored".to_string(),
            OffsetDateTime::now_utc(),
            "wallet-456".to_string(),
            "corr-789".to_string(),
            json!({}),
        );

        assert_eq!(payload.event_name(), "stored");
        assert_eq!(payload.event_namespace(), Some("credential"));
    }

    #[test]
    fn test_event_name_without_namespace() {
        let payload = WebhookPayload::new(
            "evt-123".to_string(),
            "simple_event".to_string(),
            OffsetDateTime::now_utc(),
            "wallet-456".to_string(),
            "corr-789".to_string(),
            json!({}),
        );

        assert_eq!(payload.event_name(), "simple_event");
        assert_eq!(payload.event_namespace(), Some("simple_event"));
    }

    #[test]
    fn test_webhook_response_acknowledged() {
        let response = WebhookResponse::acknowledged();
        assert!(response.acknowledged);
        assert!(response.message.is_none());
        assert!(response.processing_id.is_none());
    }

    #[test]
    fn test_webhook_response_with_message() {
        let response = WebhookResponse::with_message("Received successfully".to_string());
        assert!(response.acknowledged);
        assert_eq!(response.message, Some("Received successfully".to_string()));
    }

    #[test]
    fn test_webhook_response_with_processing_id() {
        let response = WebhookResponse::with_processing_id("proc-123".to_string());
        assert!(response.acknowledged);
        assert_eq!(response.processing_id, Some("proc-123".to_string()));
    }

    #[test]
    fn test_delivery_status_pending() {
        let status = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string());

        assert_eq!(status.subscription_id, "sub-123");
        assert_eq!(status.event_id, "evt-456");
        assert_eq!(status.attempt, 0);
        assert_eq!(status.status, DeliveryState::Pending);
    }

    #[test]
    fn test_delivery_status_in_progress() {
        let status =
            DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string()).in_progress(1);

        assert_eq!(status.attempt, 1);
        assert_eq!(status.status, DeliveryState::InProgress);
    }

    #[test]
    fn test_delivery_status_succeeded() {
        let status = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string())
            .in_progress(1)
            .succeeded(200, 150);

        assert_eq!(status.status, DeliveryState::Succeeded);
        assert_eq!(status.status_code, Some(200));
        assert_eq!(status.response_time_ms, Some(150));
    }

    #[test]
    fn test_delivery_status_failed() {
        let next_retry = OffsetDateTime::now_utc() + Duration::seconds(100);
        let status = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string())
            .in_progress(1)
            .failed(Some(500), "Server error".to_string(), Some(next_retry));

        assert_eq!(status.status, DeliveryState::Failed);
        assert_eq!(status.status_code, Some(500));
        assert_eq!(status.error, Some("Server error".to_string()));
        assert!(status.next_retry_at.is_some());
    }

    #[test]
    fn test_delivery_status_permanent_failure() {
        let status = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string())
            .permanent_failure("Max retries exceeded".to_string());

        assert_eq!(status.status, DeliveryState::PermanentFailure);
        assert_eq!(status.error, Some("Max retries exceeded".to_string()));
        assert!(status.next_retry_at.is_none());
    }

    #[test]
    fn test_delivery_state_serialization() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&DeliveryState::Pending)?,
            r#""pending""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryState::Succeeded)?,
            r#""succeeded""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryState::Failed)?,
            r#""failed""#
        );
        Ok(())
    }
}
