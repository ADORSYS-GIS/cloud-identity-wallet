//! Notification Endpoint models for OpenID4VCI §11.
//!
//! The Notification Endpoint allows the Wallet to inform the Credential Issuer
//! about events related to issued Credentials (e.g. successful storage,
//! deletion by the End-User, or a processing failure).
//!
//! See [OpenID4VCI §11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint).

use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind};

use super::utils::is_allowed_ascii_byte;

/// Notification event types defined in OpenID4VCI §11.1.
///
/// Indicates what happened to the Credential(s) identified by a
/// `notification_id` after issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// The Credentials were successfully stored in the Wallet.
    CredentialAccepted,

    /// The Credential issuance failed for a non-user reason
    /// (e.g. storage error, format incompatibility).
    CredentialFailure,

    /// The End-User explicitly deleted or rejected the Credential.
    CredentialDeleted,
}

impl std::fmt::Display for NotificationEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Notification Request sent by the Wallet to the Credential Issuer.
///
/// Defined in [OpenID4VCI §11.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-request).
///
/// # Wire format
///
/// ```json
/// {
///   "notification_id": "3fwe98js",
///   "event": "credential_accepted"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Identifier received in the Credential Response or Deferred Credential
    /// Response, identifying the issuance flow.
    pub notification_id: String,

    /// Type of the notification event.
    pub event: NotificationEvent,

    /// Human-readable ASCII text providing additional information.
    ///
    /// Characters are restricted to `%x20-21 / %x23-5B / %x5D-7E`
    /// (printable ASCII excluding `\` and DEL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

impl NotificationRequest {
    /// Creates a new notification request with the required fields.
    pub fn new(notification_id: impl Into<String>, event: NotificationEvent) -> Self {
        Self {
            notification_id: notification_id.into(),
            event,
            event_description: None,
        }
    }

    /// Sets the optional human-readable event description.
    pub fn with_event_description(mut self, description: impl Into<String>) -> Self {
        self.event_description = Some(description.into());
        self
    }

    /// Validates the notification request according to OpenID4VCI §11.1.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidNotificationRequest`] when:
    /// - `notification_id` is empty or contains only whitespace.
    /// - `event_description` contains characters outside the allowed set
    ///   (`%x20-21 / %x23-5B / %x5D-7E`).
    pub fn validate(&self) -> crate::errors::Result<()> {
        if self.notification_id.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidNotificationRequest,
                "notification_id must not be empty",
            ));
        }

        if let Some(ref desc) = self.event_description {
            if let Some(pos) = desc.bytes().position(|b| !is_allowed_ascii_byte(b)) {
                return Err(Error::message(
                    ErrorKind::InvalidNotificationRequest,
                    format!("event_description contains disallowed character at byte offset {pos}"),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // NotificationEvent serialization

    #[test]
    fn serialize_credential_accepted() {
        let json = serde_json::to_value(NotificationEvent::CredentialAccepted)
            .expect("Failed to serialize");

        assert_eq!(json, json!("credential_accepted"));
    }

    #[test]
    fn serialize_credential_failure() {
        let json = serde_json::to_value(NotificationEvent::CredentialFailure)
            .expect("Failed to serialize");

        assert_eq!(json, json!("credential_failure"));
    }

    #[test]
    fn serialize_credential_deleted() {
        let json = serde_json::to_value(NotificationEvent::CredentialDeleted)
            .expect("Failed to serialize");

        assert_eq!(json, json!("credential_deleted"));
    }

    #[test]
    fn deserialize_all_event_types() {
        let cases = [
            (
                "\"credential_accepted\"",
                NotificationEvent::CredentialAccepted,
            ),
            (
                "\"credential_failure\"",
                NotificationEvent::CredentialFailure,
            ),
            (
                "\"credential_deleted\"",
                NotificationEvent::CredentialDeleted,
            ),
        ];

        for (input, expected) in cases {
            let event: NotificationEvent =
                serde_json::from_str(input).expect("Failed to deserialize");

            assert_eq!(event, expected);
        }
    }

    #[test]
    fn deserialize_unknown_event_rejects() {
        let result = serde_json::from_str::<NotificationEvent>("\"credential_revoked\"");

        assert!(result.is_err());
    }

    #[test]
    fn event_display_matches_wire_format() {
        assert_eq!(
            format!("{}", NotificationEvent::CredentialAccepted),
            "credential_accepted"
        );
        assert_eq!(
            format!("{}", NotificationEvent::CredentialFailure),
            "credential_failure"
        );
        assert_eq!(
            format!("{}", NotificationEvent::CredentialDeleted),
            "credential_deleted"
        );
    }

    #[test]
    fn serialize_minimal_request() {
        let request = NotificationRequest::new("3fwe98js", NotificationEvent::CredentialAccepted);

        let json = serde_json::to_value(&request).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "notification_id": "3fwe98js",
                "event": "credential_accepted"
            })
        );
    }

    #[test]
    fn serialize_request_with_description() {
        let request = NotificationRequest::new("3fwe98js", NotificationEvent::CredentialFailure)
            .with_event_description("Could not store the Credential. Out of storage.");

        let json = serde_json::to_value(&request).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "notification_id": "3fwe98js",
                "event": "credential_failure",
                "event_description": "Could not store the Credential. Out of storage."
            })
        );
    }

    /// Spec §11.1 — example of a successful acceptance notification.
    #[test]
    fn deserialize_spec_example_accepted() {
        let json = r#"{
            "notification_id": "3fwe98js",
            "event": "credential_accepted"
        }"#;

        let request: NotificationRequest =
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.notification_id, "3fwe98js");
        assert_eq!(request.event, NotificationEvent::CredentialAccepted);
        assert_eq!(request.event_description, None);
    }

    /// Spec §11.1 — example of a failure notification with description.
    #[test]
    fn deserialize_spec_example_failure() {
        let json = r#"{
            "notification_id": "3fwe98js",
            "event": "credential_failure",
            "event_description": "Could not store the Credential. Out of storage."
        }"#;

        let request: NotificationRequest =
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.notification_id, "3fwe98js");
        assert_eq!(request.event, NotificationEvent::CredentialFailure);
        assert_eq!(
            request.event_description.as_deref(),
            Some("Could not store the Credential. Out of storage.")
        );
    }

    /// Spec §11.1 — "The Credential Issuer MUST ignore any unrecognized parameters."
    #[test]
    fn deserialize_ignores_unknown_fields() {
        let json = r#"{
            "notification_id": "3fwe98js",
            "event": "credential_accepted",
            "some_future_field": true
        }"#;

        let request: NotificationRequest =
            serde_json::from_str(json).expect("Should ignore unknown fields");

        assert_eq!(request.notification_id, "3fwe98js");
        assert_eq!(request.event, NotificationEvent::CredentialAccepted);
    }

    #[test]
    fn deserialize_missing_notification_id_rejects() {
        let json = r#"{"event": "credential_accepted"}"#;

        assert!(serde_json::from_str::<NotificationRequest>(json).is_err());
    }

    #[test]
    fn deserialize_missing_event_rejects() {
        let json = r#"{"notification_id": "3fwe98js"}"#;

        assert!(serde_json::from_str::<NotificationRequest>(json).is_err());
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let original = NotificationRequest::new("abc-123", NotificationEvent::CredentialDeleted)
            .with_event_description("User removed credential");

        let serialized = serde_json::to_string(&original).expect("Failed to serialize");
        let deserialized: NotificationRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(original, deserialized);
    }

    // NotificationRequest::validate

    #[test]
    fn validate_valid_request_succeeds() {
        let request = NotificationRequest::new("3fwe98js", NotificationEvent::CredentialAccepted);

        assert!(request.validate().is_ok());
    }

    #[test]
    fn validate_empty_notification_id_fails() {
        let request = NotificationRequest::new("", NotificationEvent::CredentialAccepted);

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    #[test]
    fn validate_whitespace_only_notification_id_fails() {
        let request = NotificationRequest::new("   ", NotificationEvent::CredentialAccepted);

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    #[test]
    fn validate_valid_event_description_succeeds() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("Could not store the Credential. Out of storage.");

        assert!(request.validate().is_ok());
    }

    /// `\` (0x5C) is excluded from the allowed character set.
    #[test]
    fn validate_event_description_with_backslash_fails() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("path\\to\\file");

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    /// DEL (0x7F) is excluded from the allowed character set.
    #[test]
    fn validate_event_description_with_del_fails() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("bad\x7F");

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    /// Control characters (0x00–0x1F) are excluded.
    #[test]
    fn validate_event_description_with_control_chars_fails() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("line\nnewline");

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    /// `"` (0x22) is excluded from the allowed character set.
    #[test]
    fn validate_event_description_with_double_quote_fails() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("said \"hello\"");

        let err = request.validate().unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
    }

    /// Boundary characters at the edges of each allowed range must pass.
    #[test]
    fn validate_event_description_with_allowed_boundary_chars() {
        // Space (0x20), ! (0x21), # (0x23), [ (0x5B), ] (0x5D), ~ (0x7E)
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialAccepted)
            .with_event_description(" !#[]~");

        assert!(request.validate().is_ok());
    }

    #[test]
    fn validate_none_description_succeeds() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialAccepted);

        assert_eq!(request.event_description, None);
        assert!(request.validate().is_ok());
    }

    // Builder methods

    #[test]
    fn request_new_creates_without_description() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialAccepted);

        assert_eq!(request.notification_id, "id-1");
        assert_eq!(request.event, NotificationEvent::CredentialAccepted);
        assert_eq!(request.event_description, None);
    }

    #[test]
    fn request_with_event_description_sets_value() {
        let request = NotificationRequest::new("id-1", NotificationEvent::CredentialFailure)
            .with_event_description("storage full");

        assert_eq!(request.event_description.as_deref(), Some("storage full"));
    }
}
