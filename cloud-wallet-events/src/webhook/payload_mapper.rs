use crate::events::Event;
use crate::webhook::schemas::WebhookPayload;

/// Maps a domain [`Event`] to a [`WebhookPayload`] for a specific subscription.
///
/// Implementing this trait lets callers control exactly how event data is
/// transformed before delivery — which fields are included, how defaults are
/// applied, and what domain context (e.g. `wallet_id`, `correlation_id`) is
/// injected into `data`. The library ships a [`DefaultPayloadMapper`] that
/// covers common wallet-event conventions, but callers are free to provide
/// their own.
pub trait PayloadMapper: Send + Sync {
    /// Build a [`WebhookPayload`] from `event` for the given `subscription_id`.
    ///
    /// Returns `Err` if the event cannot be mapped (e.g. serialization
    /// failure). The `EventListener` will skip the subscription on error.
    fn map(
        &self,
        event: &Event,
        subscription_id: &str,
    ) -> Result<WebhookPayload, PayloadMapperError>;
}

/// Error returned by a [`PayloadMapper`].
#[derive(Debug, thiserror::Error)]
pub enum PayloadMapperError {
    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Mapping failed: {0}")]
    Mapping(String),
}

/// Default [`PayloadMapper`] that covers standard wallet-event conventions.
///
/// Injects `wallet_id` and `correlation_id` from the event's metadata into
/// the `data` object so receivers have full context. If `wallet_id` is absent
/// from metadata, the field is omitted rather than defaulted — callers who
/// need a fallback value should provide their own mapper.
///
/// # Field injection
///
/// | Metadata key     | Injected into `data` as |
/// |------------------|-------------------------|
/// | `wallet_id`      | `"wallet_id"`           |
/// | `correlation_id` | `"correlation_id"`      |
///
/// If `correlation_id` is absent, the event's own `id` is used as a fallback.
pub struct DefaultPayloadMapper;

impl PayloadMapper for DefaultPayloadMapper {
    fn map(
        &self,
        event: &Event,
        subscription_id: &str,
    ) -> Result<WebhookPayload, PayloadMapperError> {
        let mut data = event.payload.clone();

        if let Some(obj) = data.as_object_mut() {
            if let Some(wallet_id) = event.metadata.get("wallet_id").and_then(|v| v.as_str()) {
                obj.insert(
                    "wallet_id".to_string(),
                    serde_json::Value::String(wallet_id.to_string()),
                );
            }

            let correlation_id = event
                .metadata
                .get("correlation_id")
                .and_then(|v| v.as_str())
                .unwrap_or(event.id.to_string().as_str())
                .to_string();
            obj.insert(
                "correlation_id".to_string(),
                serde_json::Value::String(correlation_id),
            );
        }

        Ok(WebhookPayload::new(
            event.id.to_string(),
            subscription_id.to_string(),
            event.timestamp,
            event.event_type.as_str().to_string(),
            data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Event, EventType};
    use serde_json::json;

    fn make_event_with_meta() -> Event {
        Event::new(
            EventType::new(EventType::CREDENTIAL_STORED),
            json!({"credential_id": "cred-1"}),
        )
        .with_metadata("wallet_id", "wallet-abc")
        .with_metadata("correlation_id", "corr-xyz")
    }

    #[test]
    fn test_default_mapper_injects_wallet_and_correlation_id() {
        let mapper = DefaultPayloadMapper;
        let event = make_event_with_meta();
        let payload = mapper.map(&event, "sub-1").expect("map");

        assert_eq!(payload.webhook_id, "sub-1");
        assert_eq!(payload.delivery_id, event.id.to_string());
        assert_eq!(payload.event_type, EventType::CREDENTIAL_STORED);
        assert_eq!(payload.data["wallet_id"], "wallet-abc");
        assert_eq!(payload.data["correlation_id"], "corr-xyz");
        assert_eq!(payload.data["credential_id"], "cred-1");
    }

    #[test]
    fn test_default_mapper_omits_wallet_id_when_absent() {
        let mapper = DefaultPayloadMapper;
        let event = Event::new(
            EventType::new(EventType::CREDENTIAL_STORED),
            json!({"credential_id": "cred-x"}),
        );
        let payload = mapper.map(&event, "sub-1").expect("map");

        // wallet_id should not be present — mapper does not default it
        assert!(payload.data.get("wallet_id").is_none());
    }

    #[test]
    fn test_default_mapper_falls_back_to_event_id_for_correlation_id() {
        let mapper = DefaultPayloadMapper;
        let event = Event::new(EventType::new(EventType::CREDENTIAL_STORED), json!({}));
        let event_id = event.id.to_string();
        let payload = mapper.map(&event, "sub-1").expect("map");

        assert_eq!(payload.data["correlation_id"], event_id);
    }

    #[test]
    fn test_custom_mapper_can_replace_default() {
        struct UpperCaseMapper;

        impl PayloadMapper for UpperCaseMapper {
            fn map(
                &self,
                event: &Event,
                subscription_id: &str,
            ) -> Result<WebhookPayload, PayloadMapperError> {
                Ok(WebhookPayload::new(
                    event.id.to_string().to_uppercase(),
                    subscription_id.to_string(),
                    event.timestamp,
                    event.event_type.as_str().to_string(),
                    event.payload.clone(),
                ))
            }
        }

        let mapper = UpperCaseMapper;
        let event = make_event_with_meta();
        let payload = mapper.map(&event, "sub-custom").expect("map");

        // delivery_id uppercased — proving the custom mapper was used
        assert_eq!(payload.delivery_id, event.id.to_string().to_uppercase());
        assert_eq!(payload.webhook_id, "sub-custom");
    }
}
