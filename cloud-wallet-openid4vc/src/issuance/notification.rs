//! Notification Endpoint models for OpenID4VCI §11.
//!
//! The Notification Endpoint allows the Wallet to inform the Credential Issuer
//! about events related to issued Credentials (e.g. successful storage,
//! deletion by the End-User, or a processing failure).
//!
//! See [OpenID4VCI §11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint).

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::errors::{Error, ErrorKind};
use crate::http::HttpError;
use crate::http::client::HttpClient;

use super::error::{NotificationErrorResponse, Oid4vciError};

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

impl NotificationEvent {
    /// Returns the canonical snake_case string representation of the event.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CredentialAccepted => "credential_accepted",
            Self::CredentialFailure => "credential_failure",
            Self::CredentialDeleted => "credential_deleted",
        }
    }
}

impl std::fmt::Display for NotificationEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// Returns [`ErrorKind::InvalidNotificationRequest`] when
    /// `notification_id` is empty or contains only whitespace.
    pub fn validate(&self) -> crate::errors::Result<()> {
        if self.notification_id.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidNotificationRequest,
                "notification_id must not be empty",
            ));
        }

        Ok(())
    }
}

/// Sends a Notification Request to the Credential Issuer's Notification Endpoint.
///
/// POSTs `request` as JSON to `endpoint` with a Bearer `token`, following
/// [OpenID4VCI §11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint).
///
/// The request is validated before sending. On success the issuer returns
/// HTTP 204 No Content (no response body). On failure the issuer returns
/// HTTP 400 with a JSON body conforming to [OpenID4VCI §11.3].
///
/// [OpenID4VCI §11.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response
///
/// # Errors
///
/// - [`ErrorKind::InvalidNotificationRequest`] — `request` fails local validation
///   (empty `notification_id` or disallowed characters in `event_description`),
///   or the server returned `"error": "invalid_notification_request"`.
/// - [`ErrorKind::InvalidNotificationId`] — the server returned HTTP 400 with
///   `"error": "invalid_notification_id"`.
/// - [`ErrorKind::HttpErrorResponse`] — any other non-2xx HTTP status.
/// - [`ErrorKind::HttpRequestFailed`] — network or TLS failure.
pub async fn send_notification(
    client: &HttpClient,
    endpoint: &str,
    token: &str,
    request: &NotificationRequest,
) -> crate::errors::Result<()> {
    request.validate()?;

    let result = client
        .request(Method::POST, endpoint)
        .bearer(token)
        .json(request)
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::HttpErrorResponse => match e.downcast::<HttpError>() {
            Ok(http_err) => {
                if http_err.status == StatusCode::BAD_REQUEST
                    && let Ok(Some(notification_err)) =
                        http_err.parse_body_as_json::<Oid4vciError<NotificationErrorResponse>>()
                {
                    let description = notification_err.error_description.unwrap_or_default();
                    return Err(match notification_err.error {
                        NotificationErrorResponse::InvalidNotificationId => {
                            Error::message(ErrorKind::InvalidNotificationId, description)
                        }
                        NotificationErrorResponse::InvalidNotificationRequest => {
                            Error::message(ErrorKind::InvalidNotificationRequest, description)
                        }
                    });
                }
                Err(Error::new(ErrorKind::HttpErrorResponse, http_err))
            }
            Err(original) => Err(original),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_wire_format_and_display() {
        let cases = [
            (NotificationEvent::CredentialAccepted, "credential_accepted"),
            (NotificationEvent::CredentialFailure, "credential_failure"),
            (NotificationEvent::CredentialDeleted, "credential_deleted"),
        ];
        for (event, wire) in cases {
            assert_eq!(serde_json::to_value(event).unwrap(), json!(wire));
            let deserialized: NotificationEvent =
                serde_json::from_str(&format!("\"{}\"", wire)).unwrap();
            assert_eq!(deserialized, event);
            assert_eq!(event.to_string(), wire);
        }
    }

    #[test]
    fn deserialize_unknown_event_rejects() {
        assert!(serde_json::from_str::<NotificationEvent>("\"credential_revoked\"").is_err());
    }

    /// Spec §11.1 wire format — round-trip preserves all fields.
    #[test]
    fn request_round_trip() {
        let original = NotificationRequest::new("3fwe98js", NotificationEvent::CredentialFailure)
            .with_event_description("Could not store the Credential. Out of storage.");

        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(
            json,
            json!({
                "notification_id": "3fwe98js",
                "event": "credential_failure",
                "event_description": "Could not store the Credential. Out of storage."
            })
        );
        assert_eq!(
            serde_json::from_value::<NotificationRequest>(json).unwrap(),
            original
        );
    }

    /// Spec §11.1 — unrecognized parameters MUST be ignored.
    #[test]
    fn deserialize_ignores_unknown_fields() {
        let json = r#"{"notification_id":"3fwe98js","event":"credential_accepted","future":true}"#;
        assert!(serde_json::from_str::<NotificationRequest>(json).is_ok());
    }

    #[test]
    fn deserialize_rejects_missing_required_fields() {
        assert!(
            serde_json::from_str::<NotificationRequest>(r#"{"event":"credential_accepted"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<NotificationRequest>(r#"{"notification_id":"3fwe98js"}"#)
                .is_err()
        );
    }

    #[test]
    fn validate_accepts_valid_request() {
        assert!(
            NotificationRequest::new("3fwe98js", NotificationEvent::CredentialAccepted)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_rejects_blank_notification_id() {
        for id in ["", "   "] {
            let err = NotificationRequest::new(id, NotificationEvent::CredentialAccepted)
                .validate()
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidNotificationRequest);
        }
    }
}
