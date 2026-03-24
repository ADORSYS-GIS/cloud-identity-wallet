//! Core event types for the cloud wallet event bus.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// A strongly-typed event type identifier.
///
///
/// `"key.created"`.
///
/// # Well-known constants
///
/// [`EventType`] exposes a set of pre-defined constants for the core wallet
/// events:
///
/// | Constant                | Value                    |
/// |-------------------------|--------------------------|
/// | [`CREDENTIAL_STORED`]   | `"credential.stored"`    |
/// | [`CREDENTIAL_DELETED`]   | `"credential.deleted"`   |
/// | [`PRESENTATION_SUBMITTED`] | `"presentation.submitted"` |
/// | [`KEY_CREATED`]         | `"key.created"`          |
/// | [`KEY_ROTATED`]         | `"key.rotated"`          |
/// | [`KEY_REVOKED`]         | `"key.revoked"`          |
///
/// [`CREDENTIAL_STORED`]: EventType::CREDENTIAL_STORED
/// [`CREDENTIAL_DELETED`]: EventType::CREDENTIAL_DELETED
/// [`PRESENTATION_SUBMITTED`]: EventType::PRESENTATION_SUBMITTED
/// [`KEY_CREATED`]: EventType::KEY_CREATED
/// [`KEY_ROTATED`]: EventType::KEY_ROTATED
/// [`KEY_REVOKED`]: EventType::KEY_REVOKED
///
/// # Example
///
/// ```
/// use wallet_events::EventType;
///
/// // Using a built-in constant
/// let ty = EventType::new(EventType::KEY_CREATED);
/// assert_eq!(ty.as_str(), "key.created");
///
/// // Defining a custom event type
/// let custom = EventType::new("payment.initiated");
/// assert_eq!(custom.as_str(), "payment.initiated");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(pub String);

impl EventType {
    /// Event type for a credential that has been stored in the wallet.
    pub const CREDENTIAL_STORED: &str = "credential.stored";
    /// Event type for a credential that has been deleted from the wallet.
    pub const CREDENTIAL_DELETED: &str = "credential.deleted";
    /// Event type for a verifiable presentation that has been submitted.
    pub const PRESENTATION_SUBMITTED: &str = "presentation.submitted";

    /// Event type for a new cryptographic key that has been generated.
    pub const KEY_CREATED: &str = "key.created";
    /// Event type for a cryptographic key that has been rotated.
    pub const KEY_ROTATED: &str = "key.rotated";
    /// Event type for a cryptographic key that has been revoked.
    pub const KEY_REVOKED: &str = "key.revoked";

    /// Create a new [`EventType`] from any string-like value.
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::EventType;
    ///
    /// let ty = EventType::new("credential.stored");
    /// assert_eq!(ty.as_str(), "credential.stored");
    /// ```
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the event type as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A compact, immutable event envelope carrying a typed payload and metadata.
///
/// `Event` is the central data model of the crate. Every action performed
/// inside the wallet is represented as an `Event` and published to a message
/// broker. Consumers reconstruct the state of the system by processing these
/// events.
///
/// # Anatomy of an event
///
/// | Field        | Description                                                    |
/// |--------------|----------------------------------------------------------------|
/// | `id`         | Globally unique identifier (UUIDv4) assigned at creation time. |
/// | `event_type` | Dot-separated name — e.g. `"credential.stored"`.               |
/// | `version`    | Schema version (`"1.0.0"` by default).                         |
/// | `timestamp`  | UTC timestamp set at construction time.                        |
/// | `payload`    | Arbitrary JSON value.                                          |
/// | `metadata`   | Extensible key-value map — add `wallet_id`, `correlation_id`, etc. |
///
/// # Example
///
/// ```
/// use wallet_events::{Event, EventType};
/// use serde_json::json;
///
/// let event = Event::new(
///     EventType::new(EventType::KEY_CREATED),
///     json!({ "key_id": "abc-123", "algorithm": "Ed25519" }),
/// )
/// .with_metadata("wallet_id", "wallet-42")
/// .with_metadata("correlation_id", "req-999");
///
/// assert_eq!(event.version, "1.0.0");
/// assert!(event.metadata.contains_key("wallet_id"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Globally unique identifier for this event instance.
    pub id: Uuid,
    /// Dot-separated event type string (e.g. `"key.created"`).
    pub event_type: EventType,
    /// Schema version of the payload.
    ///
    /// Follows semantic versioning. Defaults to `"1.0.0"`. Consumers that
    /// do not recognise the version should reject the event to avoid
    /// silently misinterpreting an unknown schema.
    pub version: String,
    /// UTC timestamp recorded when the event was constructed.
    pub timestamp: OffsetDateTime,
    /// Arbitrary JSON payload carrying domain-specific data.
    pub payload: serde_json::Value,
    /// Extensible key-value metadata map.
    pub metadata: HashMap<String, Value>,
}

impl Event {
    /// Create a new [`Event`] with the given type and JSON payload.
    ///
    /// The `id` is randomly generated, `version` defaults to `"1.0.0"`, and
    /// `timestamp` is set to the current UTC time. The `metadata` map starts
    /// empty; add entries with [`with_metadata`].
    ///
    /// [`with_metadata`]: Event::with_metadata
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::{Event, EventType};
    /// use serde_json::json;
    ///
    /// let event = Event::new(
    ///     EventType::new(EventType::CREDENTIAL_STORED),
    ///     json!({ "issuer": "did:example:issuer" }),
    /// );
    ///
    /// assert_eq!(event.event_type.as_str(), "credential.stored");
    /// assert_eq!(event.version, "1.0.0");
    /// ```
    pub fn new(event_type: EventType, payload: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            version: "1.0.0".to_string(),
            timestamp: OffsetDateTime::now_utc(),
            payload,
            metadata: HashMap::new(),
        }
    }

    /// Override the schema version of this event (builder-style).
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::{Event, EventType};
    /// use serde_json::json;
    ///
    /// let event = Event::new(EventType::new("key.rotated"), json!({}))
    ///     .with_version("2.0.0");
    ///
    /// assert_eq!(event.version, "2.0.0");
    /// ```
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Attach a metadata key-value pair to this event (builder-style).
    ///
    /// Calling this method multiple times inserts multiple entries.
    /// Duplicate keys overwrite the previous value.
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::{Event, EventType};
    /// use serde_json::json;
    ///
    /// let event = Event::new(EventType::new("key.created"), json!({}))
    ///     .with_metadata("wallet_id", "wallet-1")
    ///     .with_metadata("correlation_id", "corr-42");
    ///
    /// assert_eq!(
    ///     event.metadata["wallet_id"].as_str().unwrap(),
    ///     "wallet-1"
    /// );
    /// ```
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Deserialize the raw JSON payload into a concrete type `T`.
    ///
    /// # Errors
    ///
    /// Returns a [`serde_json::Error`] when the payload cannot be
    /// deserialized as `T` (e.g. a required field is missing or the JSON
    /// type does not match).
    ///
    /// # Example
    ///
    /// ```
    /// use wallet_events::{Event, EventType};
    /// use serde::Deserialize;
    /// use serde_json::json;
    ///
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct KeyPayload { key_id: String }
    ///
    /// let event = Event::new(
    ///     EventType::new(EventType::KEY_CREATED),
    ///     json!({ "key_id": "abc-123" }),
    /// );
    ///
    /// let typed: KeyPayload = event.payload().unwrap();
    /// assert_eq!(typed.key_id, "abc-123");
    /// ```
    pub fn payload<T: for<'de> Deserialize<'de>>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.payload.clone())
    }
}
