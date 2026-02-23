use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(pub String);

impl EventType {
    pub const CREDENTIAL_STORED: &str = "credential.stored";
    pub const CREDENTIAL_DELETED: &str = "credential.deleted";
    pub const PRESENTATION_SUBMITTED: &str = "presentation.submitted";

    pub const KEY_CREATED: &str = "key.created";
    pub const KEY_ROTATED: &str = "key.rotated";
    pub const KEY_REVOKED: &str = "key.revoked";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unified event model with fixed metadata and flexible payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub event_type: EventType,
    pub version: String,
    pub timestamp: OffsetDateTime,
    pub payload: serde_json::Value,
    /// Additional metadata (extensible key-value pairs)
    pub metadata: HashMap<String, Value>,
}

impl Event {
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

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn payload(&self) -> &serde_json::Value {
        &self.payload
    }
}
