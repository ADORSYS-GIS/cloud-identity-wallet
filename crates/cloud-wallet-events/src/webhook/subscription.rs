use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Webhook subscription configuration
#[derive(Debug, Clone)]
pub struct WebhookSubscription {
    pub id: String,

    pub url: String,

    pub event_types: HashSet<String>,

    pub auth: WebhookAuth,
}

impl Serialize for WebhookSubscription {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("WebhookSubscription", 4)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("url", &self.url)?;
        s.serialize_field("event_types", &self.event_types)?;
        s.serialize_field("auth", &self.auth)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for WebhookSubscription {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            id: String,
            url: String,
            #[serde(default)]
            event_types: HashSet<String>,
            auth: WebhookAuth,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self {
            id: raw.id,
            url: raw.url,
            event_types: raw.event_types,
            auth: raw.auth,
        })
    }
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

/// Authentication method for webhook delivery.
#[derive(Clone)]
pub enum WebhookAuth {
    /// No authentication (not recommended for production).
    None,

    /// HMAC-SHA256 signature delivered in the `X-iGrant-Signature` header.
    HmacSha256 { secret: Arc<SecretSlice<u8>> },

    /// Bearer token delivered in the `Authorization` header.
    BearerToken { token: Arc<SecretSlice<u8>> },
}

impl WebhookAuth {
    /// Create HMAC-SHA256 authentication.
    pub fn hmac_sha256(secret: impl Into<Vec<u8>>) -> Self {
        Self::HmacSha256 {
            secret: Arc::new(SecretSlice::from(secret.into())),
        }
    }

    /// Create bearer token authentication.
    ///
    /// Same ergonomics as [`hmac_sha256`](Self::hmac_sha256).
    pub fn bearer_token(token: impl Into<Vec<u8>>) -> Self {
        Self::BearerToken {
            token: Arc::new(SecretSlice::from(token.into())),
        }
    }
}

/// `WebhookAuth` intentionally does not derive `Debug` to prevent secrets
/// from appearing in logs or panic output. This manual impl redacts them.
impl std::fmt::Debug for WebhookAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "WebhookAuth::None"),
            Self::HmacSha256 { .. } => {
                write!(f, "WebhookAuth::HmacSha256 {{ secret: [REDACTED] }}")
            }
            Self::BearerToken { .. } => {
                write!(f, "WebhookAuth::BearerToken {{ token: [REDACTED] }}")
            }
        }
    }
}

/// Serialise `WebhookAuth` — only the variant tag is written; secrets are
/// always omitted regardless of the serialiser configuration.
impl Serialize for WebhookAuth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            WebhookAuth::None => map.serialize_entry("type", "none")?,
            WebhookAuth::HmacSha256 { .. } => map.serialize_entry("type", "hmac_sha256")?,
            WebhookAuth::BearerToken { .. } => map.serialize_entry("type", "bearer_token")?,
        }
        map.end()
    }
}

/// Deserialise `WebhookAuth` — reads the variant tag and an optional plaintext
/// secret/token field, immediately wrapping the value in `SecretSlice` so
/// the raw bytes are protected as soon as they leave the deserialiser.
impl<'de> Deserialize<'de> for WebhookAuth {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};

        struct WebhookAuthVisitor;

        impl<'de> Visitor<'de> for WebhookAuthVisitor {
            type Value = WebhookAuth;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a WebhookAuth object with a `type` field")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<WebhookAuth, A::Error> {
                let mut auth_type: Option<String> = None;
                let mut secret: Option<String> = None;
                let mut token: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => auth_type = Some(map.next_value()?),
                        "secret" => secret = Some(map.next_value()?),
                        "token" => token = Some(map.next_value()?),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                match auth_type.as_deref() {
                    Some("none") => Ok(WebhookAuth::None),
                    Some("hmac_sha256") => Ok(WebhookAuth::hmac_sha256(
                        secret.unwrap_or_default().into_bytes(),
                    )),
                    Some("bearer_token") => Ok(WebhookAuth::bearer_token(
                        token.unwrap_or_default().into_bytes(),
                    )),
                    Some(other) => Err(de::Error::unknown_variant(
                        other,
                        &["none", "hmac_sha256", "bearer_token"],
                    )),
                    None => Err(de::Error::missing_field("type")),
                }
            }
        }

        deserializer.deserialize_map(WebhookAuthVisitor)
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
            WebhookAuth::hmac_sha256("secret"),
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
    fn test_secret_is_redacted_in_debug_output() {
        let auth = WebhookAuth::hmac_sha256("super-secret");
        let debug = format!("{auth:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("super-secret"));

        let token_auth = WebhookAuth::bearer_token("my-token");
        let debug = format!("{token_auth:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("my-token"));
    }

    #[test]
    fn test_serialization_omits_secret() -> Result<(), serde_json::Error> {
        let subscription = WebhookSubscription::new(
            "sub-123".to_string(),
            "https://api.example.com/webhook".to_string(),
            WebhookAuth::hmac_sha256("super-secret"),
        )
        .subscribe_to(vec!["credential.stored".to_string()]);

        let json = serde_json::to_string(&subscription)?;

        // Secret must never appear in serialized output
        assert!(!json.contains("super-secret"));
        // Variant tag must be present
        assert!(json.contains("hmac_sha256"));
        Ok(())
    }

    #[test]
    fn test_deserialization_wraps_secret_in_secrecy() -> Result<(), serde_json::Error> {
        // Simulates loading a webhook config from a JSON config file
        let json = r#"{"type":"hmac_sha256","secret":"loaded-from-config"}"#;
        let auth: WebhookAuth = serde_json::from_str(json)?;

        // After deserialization the variant is correct and the debug output redacts
        assert!(matches!(auth, WebhookAuth::HmacSha256 { .. }));
        assert!(!format!("{auth:?}").contains("loaded-from-config"));
        Ok(())
    }

    #[test]
    fn test_clone_shares_arc_not_secret_bytes() {
        let auth = WebhookAuth::hmac_sha256("shared-secret");
        // Clone must succeed (Arc clone, no secret duplication)
        let _cloned = auth.clone();
    }
}
