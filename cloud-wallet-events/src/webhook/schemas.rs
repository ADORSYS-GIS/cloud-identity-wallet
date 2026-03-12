use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Webhook payload delivered to external endpoints.
///
/// Field names follow the iGrant.io OpenID4VC webhook schema:
/// <https://docs.igrant.io/docs/openid4vc-webhooks/#webhook-payload>
///
/// ```json
/// {
///   "deliveryID": "67f770eec8426b0b55e30c2e",
///   "webhookID":  "67f770936e45cf84e6880d25",
///   "timestamp":  "2025-04-10T07:19:10Z",
///   "type":       "openid.credential.offer_sent",
///   "data":       { ... event-specific fields ... }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookPayload {
    /// Unique identifier for this individual delivery attempt.
    #[serde(rename = "deliveryID")]
    pub delivery_id: String,

    /// Identifier of the webhook subscription (configuration) that matched.
    #[serde(rename = "webhookID")]
    pub webhook_id: String,

    /// ISO 8601 timestamp of when the event occurred.
    #[serde(rename = "timestamp", with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    /// Event type identifier (e.g. `"openid.credential.offer_sent"`).
    #[serde(rename = "type")]
    pub event_type: String,

    /// Event-specific payload data.
    ///
    /// Includes all domain fields such as `wallet_id`, `correlation_id`,
    /// and any event-specific fields from the originating domain event.
    pub data: Value,
}

impl WebhookPayload {
    /// Create a new webhook payload.
    ///
    /// `data` is accepted as-is. Any domain-specific field injection (e.g.
    /// `wallet_id`, `correlation_id`) is the responsibility of the caller's
    /// `PayloadMapper` implementation, keeping this struct generic.
    pub fn new(
        delivery_id: String,
        webhook_id: String,
        timestamp: OffsetDateTime,
        event_type: String,
        data: Value,
    ) -> Self {
        Self {
            delivery_id,
            webhook_id,
            timestamp,
            event_type,
            data,
        }
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
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
            "delivery-123".to_string(),
            "sub-456".to_string(),
            OffsetDateTime::now_utc(),
            "openid.credential.offer_sent".to_string(),
            json!({
                "credential_id": "cred-123",
                "credential_type": "UniversityDegree",
                "wallet_id": "wallet-456",
                "correlation_id": "corr-789"
            }),
        );

        assert_eq!(payload.delivery_id, "delivery-123");
        assert_eq!(payload.webhook_id, "sub-456");
        assert_eq!(payload.event_type, "openid.credential.offer_sent");
        assert_eq!(payload.data["wallet_id"], "wallet-456");
        assert_eq!(payload.data["correlation_id"], "corr-789");
        assert_eq!(payload.data["credential_id"], "cred-123");
    }

    #[test]
    fn test_webhook_payload_serialization() -> Result<(), serde_json::Error> {
        let payload = WebhookPayload::new(
            "delivery-123".to_string(),
            "sub-456".to_string(),
            OffsetDateTime::now_utc(),
            "openid.credential.offer_sent".to_string(),
            json!({"test": "data", "wallet_id": "wallet-456", "correlation_id": "corr-789"}),
        );

        let json_str = payload.to_json()?;
        let parsed: Value = serde_json::from_str(&json_str)?;

        // Field names must follow the reference schema
        assert!(parsed.get("deliveryID").is_some());
        assert!(parsed.get("webhookID").is_some());
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("type").is_some());
        assert!(parsed.get("data").is_some());

        // Legacy top-level fields must not be present
        assert!(parsed.get("event_id").is_none());
        assert!(parsed.get("wallet_id").is_none());
        assert!(parsed.get("correlation_id").is_none());

        // wallet_id and correlation_id must be inside data
        assert!(parsed["data"].get("wallet_id").is_some());
        assert!(parsed["data"].get("correlation_id").is_some());

        let deserialized: WebhookPayload = serde_json::from_str(&json_str)?;
        assert_eq!(payload.delivery_id, deserialized.delivery_id);
        assert_eq!(payload.event_type, deserialized.event_type);
        Ok(())
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
