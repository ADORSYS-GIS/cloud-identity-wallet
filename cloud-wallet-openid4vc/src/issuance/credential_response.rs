//! Credential Response data models for OpenID4VCI.
//!
//! This module implements the response data models as defined in
//! [OpenID4VCI Section 8.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response).

use serde::{Deserialize, Serialize};

/// One issued credential object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialObject {
    /// The issued credential.
    ///
    /// The encoding of the Credential depends on the Credential Format and MAY be a string or an object.
    pub credential: serde_json::Value,
}

impl CredentialObject {
    pub fn new(credential: serde_json::Value) -> Self {
        Self { credential }
    }

    pub fn new_string(credential: impl Into<String>) -> Self {
        Self::new(serde_json::Value::String(credential.into()))
    }
}

/// Successful immediate credential response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmediateCredentialResponse {
    /// Array of one or more issued credentials.
    pub credentials: Vec<CredentialObject>,

    /// Identifier for notification requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
}

impl ImmediateCredentialResponse {
    pub fn new(credentials: Vec<CredentialObject>) -> Self {
        Self {
            credentials,
            notification_id: None,
        }
    }

    pub fn with_notification_id(mut self, id: impl Into<String>) -> Self {
        self.notification_id = Some(id.into());
        self
    }
}

/// Successful deferred credential response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredPending {
    /// Transaction ID for querying the deferred credential.
    pub transaction_id: String,

    /// Minimum interval in seconds before retrying.
    pub interval: u64,
}

impl DeferredPending {
    pub fn new(transaction_id: impl Into<String>, interval: u64) -> Self {
        Self {
            transaction_id: transaction_id.into(),
            interval,
        }
    }
}

/// Credential endpoint response.
///
/// Per §8.3, this is either an immediate response with `credentials`, or a deferred response
/// with `transaction_id` and `interval`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialResponse {
    Immediate(ImmediateCredentialResponse),
    Deferred(DeferredPending),
}

/// The two possible outcomes when polling the deferred credential endpoint.
///
/// Defined in [OpenID4VCI §9.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeferredCredentialResult {
    // Pending MUST come first — serde tries variants in order.
    /// The credential is not yet available. Retry after `interval` seconds.
    Pending(DeferredPending),
    /// The credential is ready.
    Ready(ImmediateCredentialResponse),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_credential_response() {
        let response = CredentialResponse::Immediate(ImmediateCredentialResponse::new(vec![
            CredentialObject::new_string("eyJhbGciOiJFUzI1NiJ9..."),
        ]));

        let json = serde_json::to_string(&response).expect("Failed to serialize");

        assert!(json.contains("\"credentials\":[{"));
        assert!(json.contains("\"credential\":\"eyJhbGciOiJFUzI1NiJ9"));
    }

    #[test]
    fn deserialize_credential_response() {
        let json = r#"{
            "credentials": [
                {"credential": "eyJhbGciOiJFUzI1NiJ9..."}
            ]
        }"#;

        let response: CredentialResponse =
            serde_json::from_str(json).expect("Failed to deserialize");

        match response {
            CredentialResponse::Immediate(resp) => {
                assert_eq!(resp.credentials.len(), 1);
                assert_eq!(
                    resp.credentials[0].credential,
                    serde_json::Value::String("eyJhbGciOiJFUzI1NiJ9...".to_string())
                );
            }
            CredentialResponse::Deferred(_) => panic!("Expected Immediate response"),
        }
    }

    #[test]
    fn serialize_deferred_pending() {
        let response = DeferredPending::new("tx-123", 5);

        let json = serde_json::to_string(&response).expect("Failed to serialize");

        assert!(json.contains("\"transaction_id\":\"tx-123\""));
        assert!(json.contains("\"interval\":5"));
    }

    #[test]
    fn deserialize_deferred_pending() {
        let json = r#"{
            "transaction_id": "tx-123",
            "interval": 5
        }"#;

        let response: DeferredPending = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(response.transaction_id, "tx-123");
        assert_eq!(response.interval, 5);
    }

    #[test]
    fn deserialize_deferred_result_pending() {
        let json = r#"{
            "transaction_id": "tx-123",
            "interval": 5
        }"#;

        let result: DeferredCredentialResult =
            serde_json::from_str(json).expect("Failed to deserialize");

        match result {
            DeferredCredentialResult::Pending(pending) => {
                assert_eq!(pending.transaction_id, "tx-123");
                assert_eq!(pending.interval, 5);
            }
            DeferredCredentialResult::Ready(_) => panic!("Expected Pending variant"),
        }
    }

    #[test]
    fn deserialize_deferred_result_ready() {
        let json = r#"{
            "credentials": [
                {"credential": "eyJhbGciOiJFUzI1NiJ9..."}
            ]
        }"#;

        let result: DeferredCredentialResult =
            serde_json::from_str(json).expect("Failed to deserialize");

        match result {
            DeferredCredentialResult::Ready(response) => {
                assert_eq!(response.credentials.len(), 1);
                assert_eq!(
                    response.credentials[0].credential,
                    serde_json::Value::String("eyJhbGciOiJFUzI1NiJ9...".to_string())
                );
            }
            DeferredCredentialResult::Pending(_) => panic!("Expected Ready variant"),
        }
    }
}
