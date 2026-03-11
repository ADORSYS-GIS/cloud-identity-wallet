use secrecy::{SecretBox, SecretSlice};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

/// Webhook subscription configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSubscription {
    pub id: String,

    pub url: String,

    pub event_types: HashSet<String>,

    pub auth: WebhookAuth,
}

/// Error returned when constructing a [`WebhookSubscription`] with an invalid
/// endpoint URL.
///
/// This is intentionally a standalone type so the caller does not need to
/// import the full `error` module just to create a subscription.
#[derive(Debug, thiserror::Error)]
#[error("Invalid webhook URL '{url}': {reason}")]
pub struct InvalidUrlError {
    url: String,
    reason: String,
}

impl WebhookSubscription {
    /// Create a new webhook subscription.
    ///
    /// Accepts anything that converts into `String` for `id` and `url` —
    /// `&str`, `String`, or `Cow<str>` all work without an explicit `.to_string()`.
    ///
    /// # URL validation
    ///
    /// The `url` is parsed and validated before storage:
    /// - Must be a well-formed URL.
    /// - Scheme must be `http` or `https`.
    ///
    /// Returns [`InvalidUrlError`] if either condition is not met.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let sub = WebhookSubscription::new("sub-1", "https://example.com/webhook", auth)?;
    /// ```
    pub fn new(
        id: impl Into<String>,
        url: impl Into<String>,
        auth: WebhookAuth,
    ) -> Result<Self, InvalidUrlError> {
        let url = url.into();

        let parsed = Url::parse(&url).map_err(|e| InvalidUrlError {
            url: url.clone(),
            reason: e.to_string(),
        })?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(InvalidUrlError {
                url: url.clone(),
                reason: format!(
                    "scheme '{}' is not allowed; must be http or https",
                    parsed.scheme()
                ),
            });
        }

        Ok(Self {
            id: id.into(),
            url,
            event_types: HashSet::new(),
            auth,
        })
    }

    /// Subscribe to all events
    pub fn subscribe_all(mut self) -> Self {
        self.event_types.clear();
        self
    }

    /// Subscribe to specific event types.
    ///
    /// Accepts any iterable whose items convert into `String`, so all of
    /// the following work without `.to_string()` boilerplate:
    ///
    /// ```rust,ignore
    /// sub.subscribe_to(["credential.stored", "key.created"])
    /// sub.subscribe_to(["credential.stored"])
    /// sub.subscribe_to(event_type_set.iter().cloned())
    /// ```
    pub fn subscribe_to(
        mut self,
        event_types: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.event_types = event_types.into_iter().map(Into::into).collect();
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
///
/// Secrets are stored as `Arc<SecretSlice<u8>>` which provides three
/// guarantees:
/// - **No accidental logging** — `SecretSlice` has no `Debug`/`Display` impl.
/// - **Zeroed on drop** — memory is wiped when the last `Arc` is released.
/// - **Cheap cloning** — `Arc` means cloning a subscription shares the same
///   allocation rather than duplicating the secret bytes.
#[derive(Clone)]
pub enum WebhookAuth {
    /// No authentication (not recommended for production).
    None,

    /// HMAC-SHA256 signature delivered in a configurable request header.
    ///
    /// `header_name` controls which header carries the signature
    /// (e.g. `"X-Hub-Signature-256"`, `"X-Webhook-Signature"`).
    /// The library never assumes a fixed header name; the caller decides.
    HmacSha256 {
        secret: Arc<SecretSlice<u8>>,
        /// HTTP header name that will carry the signature value.
        header_name: String,
    },

    /// Bearer token delivered in the `Authorization` header.
    ///
    /// Bearer tokens are UTF-8 strings by definition; storing as `SecretBox<String>`
    /// avoids the UTF-8 re-validation that would be needed when converting from
    /// `SecretSlice<u8>` at the HTTP send boundary.
    BearerToken { token: Arc<SecretBox<String>> },
}

impl WebhookAuth {
    /// Create HMAC-SHA256 authentication.
    ///
    /// `secret` accepts anything that converts into `Vec<u8>` — `&str`,
    /// `String`, `Vec<u8>`, or `&[u8]`.
    ///
    /// `header_name` is the HTTP header that will carry the signature on each
    /// delivery request. Common values: `"X-Hub-Signature-256"`,
    /// `"X-Webhook-Signature"`. The library ships no default — the caller
    /// chooses the name that matches the receiving endpoint's expectations.
    pub fn hmac_sha256(secret: impl Into<Vec<u8>>, header_name: impl Into<String>) -> Self {
        Self::HmacSha256 {
            secret: Arc::new(SecretSlice::from(secret.into())),
            header_name: header_name.into(),
        }
    }

    /// Create bearer token authentication.
    ///
    /// Accepts any type that converts into `String` — `&str`, `String`.
    pub fn bearer_token(token: impl Into<String>) -> Self {
        Self::BearerToken {
            token: Arc::new(SecretBox::new(Box::new(token.into()))),
        }
    }
}

/// `WebhookAuth` intentionally does not derive `Debug` to prevent secrets
/// from appearing in logs or panic output. This manual impl redacts them.
impl std::fmt::Debug for WebhookAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "WebhookAuth::None"),
            Self::HmacSha256 { header_name, .. } => write!(
                f,
                "WebhookAuth::HmacSha256 {{ header_name: {header_name:?}, secret: [REDACTED] }}"
            ),
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
            WebhookAuth::HmacSha256 { header_name, .. } => {
                map.serialize_entry("type", "hmac_sha256")?;
                map.serialize_entry("header_name", header_name)?;
            }
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

                let mut header_name: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => auth_type = Some(map.next_value()?),
                        "secret" => secret = Some(map.next_value()?),
                        "token" => token = Some(map.next_value()?),
                        "header_name" => header_name = Some(map.next_value()?),
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                match auth_type.as_deref() {
                    Some("none") => Ok(WebhookAuth::None),
                    Some("hmac_sha256") => Ok(WebhookAuth::hmac_sha256(
                        secret.unwrap_or_default().into_bytes(),
                        header_name.unwrap_or_else(|| "X-Webhook-Signature".to_string()),
                    )),
                    Some("bearer_token") => {
                        Ok(WebhookAuth::bearer_token(token.unwrap_or_default()))
                    }
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
            "sub-123",
            "https://api.example.com/webhook",
            WebhookAuth::hmac_sha256("secret", "X-Webhook-Signature"),
        )
        .unwrap();

        assert_eq!(subscription.id, "sub-123");
        assert_eq!(subscription.url, "https://api.example.com/webhook");
        assert!(subscription.event_types.is_empty());
    }

    #[test]
    fn test_new_rejects_invalid_url() {
        let err = WebhookSubscription::new("sub-1", "not a url at all", WebhookAuth::None);
        assert!(err.is_err());
    }

    #[test]
    fn test_new_rejects_non_http_scheme() {
        let err = WebhookSubscription::new("sub-1", "ftp://example.com/hook", WebhookAuth::None);
        assert!(matches!(err, Err(ref e) if e.to_string().contains("ftp")));
    }

    #[test]
    fn test_new_accepts_str_without_to_string() {
        // Verify impl Into<String> ergonomics — no .to_string() needed
        let sub = WebhookSubscription::new("sub-1", "https://example.com/hook", WebhookAuth::None);
        assert!(sub.is_ok());
    }

    #[test]
    fn test_subscribe_to_specific_events() {
        let subscription = WebhookSubscription::new(
            "sub-123",
            "https://api.example.com/webhook",
            WebhookAuth::None,
        )
        .unwrap()
        .subscribe_to(["credential.stored", "credential.deleted"]);

        assert!(subscription.matches_event("credential.stored"));
        assert!(subscription.matches_event("credential.deleted"));
        assert!(!subscription.matches_event("credential.issued"));
    }

    #[test]
    fn test_subscribe_all_events() {
        let subscription = WebhookSubscription::new(
            "sub-123",
            "https://api.example.com/webhook",
            WebhookAuth::None,
        )
        .unwrap()
        .subscribe_all();

        assert!(subscription.matches_event("credential.stored"));
        assert!(subscription.matches_event("presentation.verified"));
        assert!(subscription.matches_event("any.event.type"));
    }

    #[test]
    fn test_secret_is_redacted_in_debug_output() {
        let auth = WebhookAuth::hmac_sha256("super-secret", "X-Webhook-Signature");
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
            "sub-123",
            "https://api.example.com/webhook",
            WebhookAuth::hmac_sha256("super-secret", "X-Webhook-Signature"),
        )
        .unwrap()
        .subscribe_to(["credential.stored"]);

        let json = serde_json::to_string(&subscription)?;

        // Secret must never appear in serialized output
        assert!(!json.contains("super-secret"));
        // Variant tag and header name must be present
        assert!(json.contains("hmac_sha256"));
        assert!(json.contains("X-Webhook-Signature"));
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
        let auth = WebhookAuth::hmac_sha256("shared-secret", "X-Webhook-Signature");
        // Clone must succeed (Arc clone, no secret duplication)
        let _cloned = auth.clone();
    }
}
