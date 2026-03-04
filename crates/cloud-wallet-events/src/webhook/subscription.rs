use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Webhook subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookSubscription {
    pub id: String,

    pub url: String,

    pub event_types: HashSet<String>,

    pub auth: WebhookAuth,
}

impl WebhookSubscription {
    /// Create a new webhook subscription
    pub fn new(id: String, url: String, auth: WebhookAuth) -> Self {
        Self {
            id,
            url,
            event_types: HashSet::new(),
            auth,
        }
    }

    /// Subscribe to all events
    pub fn subscribe_all(mut self) -> Self {
        self.event_types.clear();
        self
    }

    /// Subscribe to specific event types
    pub fn subscribe_to(mut self, event_types: Vec<String>) -> Self {
        self.event_types = event_types.into_iter().collect();
        self
    }

    /// Check if this subscription should receive a given event type
    pub fn matches_event(&self, event_type: &str) -> bool {
        // Empty set means subscribe to all events
        if self.event_types.is_empty() {
            return true;
        }

        self.event_types.contains(event_type)
    }
}

/// Authentication method for webhook delivery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebhookAuth {
    /// No authentication (not recommended for production)
    None,

    /// HMAC-SHA256 signature in X-Webhook-Signature header
    HmacSha256 {
        /// Secret key for HMAC signing
        #[serde(skip_serializing, default)]
        secret: String,
    },

    /// Bearer token in Authorization header
    BearerToken {
        /// Bearer token value
        #[serde(skip_serializing, default)]
        token: String,
    },
}

impl WebhookAuth {
    /// Create HMAC-SHA256 authentication
    pub fn hmac_sha256(secret: String) -> Self {
        Self::HmacSha256 { secret }
    }

    /// Create bearer token authentication
    pub fn bearer_token(token: String) -> Self {
        Self::BearerToken { token }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_subscription_creation() {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::hmac_sha256("secret".to_string()),
        );

        assert_eq!(subscription.id, "sub-123");
        assert_eq!(subscription.url, "https://api.example.com/webhook");
        assert!(subscription.event_types.is_empty());
    }

    #[test]
    fn test_subscribe_to_specific_events() {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec![
            "credential.stored".to_string(),
            "credential.deleted".to_string(),
        ]);

        assert!(subscription.matches_event("credential.stored"));
        assert!(subscription.matches_event("credential.deleted"));
        assert!(!subscription.matches_event("credential.issued"));
    }

    #[test]
    fn test_subscribe_all_events() {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        assert!(subscription.matches_event("credential.stored"));
        assert!(subscription.matches_event("presentation.verified"));
        assert!(subscription.matches_event("any.event.type"));
    }

    #[test]
    fn test_serialization() -> Result<(), serde_json::Error> {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::hmac_sha256("secret".to_string()),
        )
        .subscribe_to(vec!["credential.stored".to_string()]);

        let json = serde_json::to_string(&subscription)?;
        let deserialized: WebhookSubscription = serde_json::from_str(&json)?;

        assert_eq!(subscription.id, deserialized.id);
        assert_eq!(subscription.url, deserialized.url);
        assert_eq!(subscription.event_types, deserialized.event_types);
        Ok(())
    }
}
