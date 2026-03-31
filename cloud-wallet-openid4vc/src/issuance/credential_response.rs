//! Credential Response models for OpenID4VCI §§8.3, 9.2.

use std::{fmt, num::NonZeroU64};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};

const CREDENTIAL_RESPONSE_FIELDS: &[&str] = &[
    "credentials",
    "transaction_id",
    "interval",
    "notification_id",
];
type CredentialResponseFields = (
    Option<Vec<CredentialObject>>,
    Option<String>,
    Option<NonZeroU64>,
    Option<String>,
);

fn deserialize_non_empty_credentials<'de, D>(
    deserializer: D,
) -> Result<Vec<CredentialObject>, D::Error>
where
    D: Deserializer<'de>,
{
    let credentials = Vec::<CredentialObject>::deserialize(deserializer)?;

    if credentials.is_empty() {
        return Err(de::Error::custom(
            "credentials must contain at least one credential",
        ));
    }

    Ok(credentials)
}

fn parse_credential_response_fields<'de, A>(
    mut map: A,
) -> Result<CredentialResponseFields, A::Error>
where
    A: MapAccess<'de>,
{
    let mut credentials = None;
    let mut transaction_id = None;
    let mut interval = None;
    let mut notification_id = None;

    while let Some(key) = map.next_key::<String>()? {
        match key.as_str() {
            "credentials" => {
                if credentials.is_some() {
                    return Err(de::Error::duplicate_field("credentials"));
                }

                let value = map.next_value::<Vec<CredentialObject>>()?;

                if value.is_empty() {
                    return Err(de::Error::custom(
                        "credentials must contain at least one credential",
                    ));
                }

                credentials = Some(value);
            }
            "transaction_id" => {
                if transaction_id.is_some() {
                    return Err(de::Error::duplicate_field("transaction_id"));
                }

                transaction_id = Some(map.next_value::<String>()?);
            }
            "interval" => {
                if interval.is_some() {
                    return Err(de::Error::duplicate_field("interval"));
                }

                interval = Some(map.next_value::<NonZeroU64>()?);
            }
            "notification_id" => {
                if notification_id.is_some() {
                    return Err(de::Error::duplicate_field("notification_id"));
                }

                notification_id = Some(map.next_value::<String>()?);
            }
            _ => return Err(de::Error::unknown_field(&key, CREDENTIAL_RESPONSE_FIELDS)),
        }
    }

    Ok((credentials, transaction_id, interval, notification_id))
}

fn credential_response_from_parts<E>(
    credentials: Option<Vec<CredentialObject>>,
    transaction_id: Option<String>,
    interval: Option<NonZeroU64>,
    notification_id: Option<String>,
) -> Result<CredentialResponse, E>
where
    E: de::Error,
{
    match (credentials, transaction_id, interval, notification_id) {
        (Some(credentials), None, None, notification_id) => {
            Ok(CredentialResponse::Immediate(ImmediateCredentialResponse {
                credentials,
                notification_id,
            }))
        }
        (None, Some(transaction_id), Some(interval), None) => {
            Ok(CredentialResponse::Deferred(DeferredPending {
                transaction_id,
                interval,
            }))
        }
        (Some(_), _, Some(_), _) | (Some(_), Some(_), _, _) => Err(de::Error::custom(
            "credentials is mutually exclusive with transaction_id and interval",
        )),
        (None, Some(_), None, _) | (None, None, Some(_), _) => Err(de::Error::custom(
            "interval and transaction_id must be used together",
        )),
        (None, Some(_), Some(_), Some(_)) | (None, None, None, Some(_)) => Err(de::Error::custom(
            "notification_id must not be used when credentials are absent",
        )),
        (None, None, None, None) => Err(de::Error::custom(
            "credential response must contain either credentials or transaction_id with interval",
        )),
    }
}

fn deferred_credential_result_from_parts<E>(
    credentials: Option<Vec<CredentialObject>>,
    transaction_id: Option<String>,
    interval: Option<NonZeroU64>,
    notification_id: Option<String>,
) -> Result<DeferredCredentialResult, E>
where
    E: de::Error,
{
    match credential_response_from_parts(credentials, transaction_id, interval, notification_id)? {
        CredentialResponse::Immediate(response) => Ok(DeferredCredentialResult::Ready(response)),
        CredentialResponse::Deferred(response) => Ok(DeferredCredentialResult::Pending(response)),
    }
}

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
#[serde(deny_unknown_fields)]
pub struct ImmediateCredentialResponse {
    /// Array of one or more issued credentials.
    #[serde(deserialize_with = "deserialize_non_empty_credentials")]
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
#[serde(deny_unknown_fields)]
pub struct DeferredPending {
    /// Transaction ID for querying the deferred credential.
    pub transaction_id: String,

    /// Minimum interval in seconds before retrying.
    pub interval: NonZeroU64,
}

impl DeferredPending {
    pub fn new(transaction_id: impl Into<String>, interval: NonZeroU64) -> Self {
        Self {
            transaction_id: transaction_id.into(),
            interval,
        }
    }

    pub fn interval_seconds(&self) -> u64 {
        self.interval.get()
    }
}

/// Credential endpoint response.
///
/// Per §8.3, this is either an immediate response with `credentials`, or a deferred response
/// with `transaction_id` and `interval`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialResponse {
    Immediate(ImmediateCredentialResponse),
    Deferred(DeferredPending),
}

impl Serialize for CredentialResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Immediate(response) => response.serialize(serializer),
            Self::Deferred(response) => response.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CredentialResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialResponseVisitor;

        impl<'de> Visitor<'de> for CredentialResponseVisitor {
            type Value = CredentialResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a credential response containing either credentials or transaction_id with interval",
                )
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let (credentials, transaction_id, interval, notification_id) =
                    parse_credential_response_fields(map)?;

                credential_response_from_parts(
                    credentials,
                    transaction_id,
                    interval,
                    notification_id,
                )
            }
        }

        deserializer.deserialize_map(CredentialResponseVisitor)
    }
}

/// The two possible outcomes when polling the deferred credential endpoint.
///
/// Defined in [OpenID4VCI §9.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredCredentialResult {
    /// The credential is not yet available. Retry after `interval` seconds.
    Pending(DeferredPending),
    /// The credential is ready.
    Ready(ImmediateCredentialResponse),
}

impl Serialize for DeferredCredentialResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Pending(response) => response.serialize(serializer),
            Self::Ready(response) => response.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DeferredCredentialResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeferredCredentialResultVisitor;

        impl<'de> Visitor<'de> for DeferredCredentialResultVisitor {
            type Value = DeferredCredentialResult;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a deferred credential response containing either pending or ready fields",
                )
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let (credentials, transaction_id, interval, notification_id) =
                    parse_credential_response_fields(map)?;

                deferred_credential_result_from_parts(
                    credentials,
                    transaction_id,
                    interval,
                    notification_id,
                )
            }
        }

        deserializer.deserialize_map(DeferredCredentialResultVisitor)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

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
        let response = DeferredPending::new("tx-123", NonZeroU64::new(5).expect("non-zero"));

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
        assert_eq!(response.interval.get(), 5);
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
                assert_eq!(pending.interval.get(), 5);
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

    #[test]
    fn deserialize_deferred_result_rejects_zero_interval() {
        let json = r#"{
            "transaction_id": "tx-123",
            "interval": 0
        }"#;

        let error = serde_json::from_str::<DeferredCredentialResult>(json).unwrap_err();

        assert!(error.to_string().contains("nonzero"));
    }
}
