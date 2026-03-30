//! Credential Response models for OpenID4VCI §§8.3, 9.2.

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct RawCredentialResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<CredentialObject>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notification_id: Option<String>,
}

enum ParsedCredentialResponse {
    Immediate(ImmediateCredentialResponse),
    Deferred(DeferredPending),
}

fn immediate_from_parts(
    credentials: Vec<CredentialObject>,
    notification_id: Option<String>,
) -> Result<ImmediateCredentialResponse, String> {
    if credentials.is_empty() {
        return Err("credentials must contain at least one credential".to_string());
    }

    Ok(ImmediateCredentialResponse {
        credentials,
        notification_id,
    })
}

fn deferred_from_parts(
    transaction_id: String,
    interval: u64,
    notification_id: Option<String>,
) -> Result<DeferredPending, String> {
    if interval == 0 {
        return Err("interval must be positive".to_string());
    }

    if notification_id.is_some() {
        return Err("notification_id must not be used when credentials are absent".to_string());
    }

    Ok(DeferredPending {
        transaction_id,
        interval,
    })
}

fn parse_raw_credential_response(
    raw: RawCredentialResponse,
) -> Result<ParsedCredentialResponse, String> {
    match (
        raw.credentials,
        raw.transaction_id,
        raw.interval,
        raw.notification_id,
    ) {
        (Some(credentials), None, None, notification_id) => {
            immediate_from_parts(credentials, notification_id)
                .map(ParsedCredentialResponse::Immediate)
        }
        (None, Some(transaction_id), Some(interval), notification_id) => {
            deferred_from_parts(transaction_id, interval, notification_id)
                .map(ParsedCredentialResponse::Deferred)
        }
        (Some(_), _, Some(_), _) | (Some(_), Some(_), _, _) => {
            Err("credentials is mutually exclusive with transaction_id and interval".to_string())
        }
        (None, Some(_), None, _) | (None, None, Some(_), _) => {
            Err("interval and transaction_id must be used together".to_string())
        }
        (None, None, None, Some(_)) => {
            Err("notification_id must not be used when credentials are absent".to_string())
        }
        (None, None, None, None) => Err(
            "credential response must contain either credentials or transaction_id with interval"
                .to_string(),
        ),
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
#[serde(try_from = "RawCredentialResponse", into = "RawCredentialResponse")]
pub enum CredentialResponse {
    Immediate(ImmediateCredentialResponse),
    Deferred(DeferredPending),
}

impl TryFrom<RawCredentialResponse> for CredentialResponse {
    type Error = String;

    fn try_from(raw: RawCredentialResponse) -> Result<Self, Self::Error> {
        match parse_raw_credential_response(raw)? {
            ParsedCredentialResponse::Immediate(response) => Ok(Self::Immediate(response)),
            ParsedCredentialResponse::Deferred(response) => Ok(Self::Deferred(response)),
        }
    }
}

impl From<CredentialResponse> for RawCredentialResponse {
    fn from(value: CredentialResponse) -> Self {
        match value {
            CredentialResponse::Immediate(response) => Self {
                credentials: Some(response.credentials),
                transaction_id: None,
                interval: None,
                notification_id: response.notification_id,
            },
            CredentialResponse::Deferred(response) => Self {
                credentials: None,
                transaction_id: Some(response.transaction_id),
                interval: Some(response.interval),
                notification_id: None,
            },
        }
    }
}

/// The two possible outcomes when polling the deferred credential endpoint.
///
/// Defined in [OpenID4VCI §9.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCredentialResponse", into = "RawCredentialResponse")]
pub enum DeferredCredentialResult {
    /// The credential is not yet available. Retry after `interval` seconds.
    Pending(DeferredPending),
    /// The credential is ready.
    Ready(ImmediateCredentialResponse),
}

impl TryFrom<RawCredentialResponse> for DeferredCredentialResult {
    type Error = String;

    fn try_from(raw: RawCredentialResponse) -> Result<Self, Self::Error> {
        match parse_raw_credential_response(raw)? {
            ParsedCredentialResponse::Immediate(response) => Ok(Self::Ready(response)),
            ParsedCredentialResponse::Deferred(response) => Ok(Self::Pending(response)),
        }
    }
}

impl From<DeferredCredentialResult> for RawCredentialResponse {
    fn from(value: DeferredCredentialResult) -> Self {
        match value {
            DeferredCredentialResult::Pending(response) => Self {
                credentials: None,
                transaction_id: Some(response.transaction_id),
                interval: Some(response.interval),
                notification_id: None,
            },
            DeferredCredentialResult::Ready(response) => Self {
                credentials: Some(response.credentials),
                transaction_id: None,
                interval: None,
                notification_id: response.notification_id,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_credential_response() {
        let response = CredentialResponse::Immediate(ImmediateCredentialResponse::new(vec![
            CredentialObject::new_string("eyJhbGciOiJFUzI1NiJ9..."),
        ]));

        let json = serde_json::to_value(&response).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "credentials": [
                    {
                        "credential": "eyJhbGciOiJFUzI1NiJ9..."
                    }
                ]
            })
        );
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

        let json = serde_json::to_value(&response).expect("Failed to serialize");

        assert_eq!(
            json,
            json!({
                "transaction_id": "tx-123",
                "interval": 5
            })
        );
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

    #[test]
    fn deserialize_credential_response_rejects_mixed_shapes() {
        let json = r#"{
            "credentials": [
                {"credential": "eyJhbGciOiJFUzI1NiJ9..."}
            ],
            "transaction_id": "tx-123",
            "interval": 5
        }"#;

        let error = serde_json::from_str::<CredentialResponse>(json).unwrap_err();

        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn deserialize_deferred_result_rejects_notification_without_credentials() {
        let json = r#"{
            "transaction_id": "tx-123",
            "interval": 5,
            "notification_id": "notify-123"
        }"#;

        let error = serde_json::from_str::<DeferredCredentialResult>(json).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("notification_id must not be used when credentials are absent")
        );
    }
}
