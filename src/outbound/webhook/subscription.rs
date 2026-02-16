use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Webhook subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookSubscription {
    pub id: String,

    pub url: String,

    pub event_types: HashSet<String>,

    pub auth: WebhookAuth,

    pub max_retries: Option<u32>,

    pub enabled: bool,

    pub description: Option<String>,
}

impl WebhookSubscription {
    /// Create a new webhook subscription
    pub fn new(id: String, url: String, auth: WebhookAuth) -> Self {
        Self {
            id,
            url,
            event_types: HashSet::new(),
            auth,
            max_retries: None,
            enabled: true,
            description: None,
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

    /// Add an event type to the subscription
    pub fn add_event_type(&mut self, event_type: String) {
        self.event_types.insert(event_type);
    }

    /// Check if this subscription should receive a given event type
    pub fn matches_event(&self, event_type: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // Empty set means subscribe to all events
        if self.event_types.is_empty() {
            return true;
        }

        self.event_types.contains(event_type)
    }

    /// Set maximum retry attempts
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Disable this subscription
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this subscription
    pub fn enable(&mut self) {
        self.enabled = true;
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

    /// Basic authentication
    Basic {
        /// Username
        username: String,
        /// Password
        #[serde(skip_serializing, default)]
        password: String,
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

    /// Create basic authentication
    pub fn basic(username: String, password: String) -> Self {
        Self::Basic { username, password }
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
        assert!(subscription.enabled);
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
    fn test_disabled_subscription_does_not_match() {
        let mut subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        subscription.disable();

        assert!(!subscription.matches_event("credential.stored"));
    }

    #[test]
    fn test_builder_pattern() {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::bearer_token("token123".to_string()),
        )
        .subscribe_to(vec!["credential.stored".to_string()])
        .with_max_retries(10)
        .with_description("Production webhook".to_string());

        assert_eq!(subscription.max_retries, Some(10));
        assert_eq!(
            subscription.description,
            Some("Production webhook".to_string())
        );
    }

    #[test]
    fn test_webhook_auth_types() {
        let hmac = WebhookAuth::hmac_sha256("secret".to_string());
        assert!(matches!(hmac, WebhookAuth::HmacSha256 { .. }));

        let bearer = WebhookAuth::bearer_token("token".to_string());
        assert!(matches!(bearer, WebhookAuth::BearerToken { .. }));

        let basic = WebhookAuth::basic("user".to_string(), "dastro".to_string());
        assert!(matches!(basic, WebhookAuth::Basic { .. }));
    }

    #[test]
    fn test_add_event_type() {
        let mut subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::None,
        );

        subscription.add_event_type("credential.stored".to_string());
        subscription.add_event_type("credential.deleted".to_string());

        assert!(subscription.matches_event("credential.stored"));
        assert!(subscription.matches_event("credential.deleted"));
        assert!(!subscription.matches_event("credential.issued"));
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
