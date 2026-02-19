use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(pub String);

impl EventType {
    pub const CREDENTIAL_OFFER_SENT: &str = "credential.offer.sent";
    pub const CREDENTIAL_OFFER_RECEIVED: &str = "credential.offer.received";
    pub const CREDENTIAL_ISSUED: &str = "credential.issued";
    pub const CREDENTIAL_ACKNOWLEDGED: &str = "credential.acknowledged";
    pub const CREDENTIAL_STORED: &str = "credential.stored";
    pub const CREDENTIAL_DELETED: &str = "credential.deleted";
    pub const PRESENTATION_REQUEST_SENT: &str = "presentation.request.sent";
    pub const PRESENTATION_REQUEST_RECEIVED: &str = "presentation.request.received";
    pub const PRESENTATION_SUBMITTED: &str = "presentation.submitted";
    pub const PRESENTATION_VERIFIED: &str = "presentation.verified";
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

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unified event model with fixed metadata and flexible payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub event_type: EventType,
    pub version: String,
    pub timestamp: OffsetDateTime,
    pub payload: Value,
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

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Common metadata for all wallet events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMetadata {
    /// Unique identifier for this event
    pub event_id: Uuid,
    /// Timestamp when the event occurred
    pub timestamp: OffsetDateTime,
    /// Correlation ID to link related events across flows
    pub correlation_id: String,
    /// Wallet instance identifier
    pub wallet_id: String,
    /// Event schema version for evolution
    pub schema_version: String,
}

impl EventMetadata {
    pub fn new(correlation_id: String, wallet_id: String) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            correlation_id,
            wallet_id,
            schema_version: "1.0.0".to_string(),
        }
    }
}

/// Main wallet event wrapper including metadata and payload
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletEvent {
    /// Common event metadata
    pub metadata: EventMetadata,
    /// Event-specific data
    pub payload: WalletEventPayload,
}

impl WalletEvent {
    pub fn new(correlation_id: String, wallet_id: String, payload: WalletEventPayload) -> Self {
        Self {
            metadata: EventMetadata::new(correlation_id, wallet_id),
            payload,
        }
    }

    pub fn event_type_name(&self) -> &'static str {
        self.payload.event_type_name()
    }

    pub fn event_type(&self) -> EventType {
        self.payload.event_type_v2()
    }

    pub fn topic_category(&self) -> &'static str {
        self.payload.topic_category()
    }
}

/// Payload enum containing all wallet event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event_type", content = "payload")]
#[non_exhaustive]
pub enum WalletEventPayload {
    // Credential Offer Events
    CredentialOfferSent(CredentialOfferSentPayload),
    CredentialOfferReceived(CredentialOfferReceivedPayload),

    // Credential Issuance Events
    CredentialIssued(CredentialIssuedPayload),
    CredentialAcknowledged(CredentialAcknowledgedPayload),

    // Credential Storage Events
    CredentialStored(CredentialStoredPayload),
    CredentialDeleted(CredentialDeletedPayload),

    // Presentation Request Events
    PresentationRequestSent(PresentationRequestSentPayload),
    PresentationRequestReceived(PresentationRequestReceivedPayload),

    // Presentation Submission Events
    PresentationSubmitted(PresentationSubmittedPayload),
    PresentationVerified(PresentationVerifiedPayload),

    // Key Operation Events
    KeyCreated(KeyCreatedPayload),
    KeyRotated(KeyRotatedPayload),
    KeyRevoked(KeyRevokedPayload),
}

impl WalletEventPayload {
    pub fn event_type_name(&self) -> &'static str {
        match self {
            WalletEventPayload::CredentialOfferSent(_) => EventType::CREDENTIAL_OFFER_SENT,
            WalletEventPayload::CredentialOfferReceived(_) => EventType::CREDENTIAL_OFFER_RECEIVED,
            WalletEventPayload::CredentialIssued(_) => EventType::CREDENTIAL_ISSUED,
            WalletEventPayload::CredentialAcknowledged(_) => EventType::CREDENTIAL_ACKNOWLEDGED,
            WalletEventPayload::CredentialStored(_) => EventType::CREDENTIAL_STORED,
            WalletEventPayload::CredentialDeleted(_) => EventType::CREDENTIAL_DELETED,
            WalletEventPayload::PresentationRequestSent(_) => EventType::PRESENTATION_REQUEST_SENT,
            WalletEventPayload::PresentationRequestReceived(_) => {
                EventType::PRESENTATION_REQUEST_RECEIVED
            }
            WalletEventPayload::PresentationSubmitted(_) => EventType::PRESENTATION_SUBMITTED,
            WalletEventPayload::PresentationVerified(_) => EventType::PRESENTATION_VERIFIED,
            WalletEventPayload::KeyCreated(_) => EventType::KEY_CREATED,
            WalletEventPayload::KeyRotated(_) => EventType::KEY_ROTATED,
            WalletEventPayload::KeyRevoked(_) => EventType::KEY_REVOKED,
        }
    }

    pub fn topic_category(&self) -> &'static str {
        match self {
            WalletEventPayload::CredentialOfferSent(_)
            | WalletEventPayload::CredentialOfferReceived(_) => "credential.offers",
            WalletEventPayload::CredentialIssued(_)
            | WalletEventPayload::CredentialAcknowledged(_) => "credential.issuance",
            WalletEventPayload::CredentialStored(_) | WalletEventPayload::CredentialDeleted(_) => {
                "credential.storage"
            }
            WalletEventPayload::PresentationRequestSent(_)
            | WalletEventPayload::PresentationRequestReceived(_) => "presentation.requests",
            WalletEventPayload::PresentationSubmitted(_)
            | WalletEventPayload::PresentationVerified(_) => "presentation.submissions",
            WalletEventPayload::KeyCreated(_)
            | WalletEventPayload::KeyRotated(_)
            | WalletEventPayload::KeyRevoked(_) => "key.operations",
        }
    }
}

impl TryFrom<WalletEvent> for Event {
    type Error = serde_json::Error;

    fn try_from(wallet_event: WalletEvent) -> Result<Self, Self::Error> {
        let payload = serde_json::to_value(&wallet_event.payload)?;
        let mut metadata = HashMap::new();
        metadata.insert(
            "correlation_id".to_string(),
            Value::String(wallet_event.metadata.correlation_id),
        );
        metadata.insert(
            "wallet_id".to_string(),
            Value::String(wallet_event.metadata.wallet_id),
        );
        metadata.insert(
            "category".to_string(),
            Value::String(wallet_event.payload.topic_category().to_string()),
        );

        Ok(Event {
            id: wallet_event.metadata.event_id,
            event_type: wallet_event.payload.event_type_v2(),
            version: wallet_event.metadata.schema_version,
            timestamp: wallet_event.metadata.timestamp,
            payload,
            metadata,
        })
    }
}

impl WalletEventPayload {
    pub fn event_type_v2(&self) -> EventType {
        match self {
            WalletEventPayload::CredentialOfferSent(_) => {
                EventType::new(EventType::CREDENTIAL_OFFER_SENT)
            }
            WalletEventPayload::CredentialOfferReceived(_) => {
                EventType::new(EventType::CREDENTIAL_OFFER_RECEIVED)
            }
            WalletEventPayload::CredentialIssued(_) => EventType::new(EventType::CREDENTIAL_ISSUED),
            WalletEventPayload::CredentialAcknowledged(_) => {
                EventType::new(EventType::CREDENTIAL_ACKNOWLEDGED)
            }
            WalletEventPayload::CredentialStored(_) => EventType::new(EventType::CREDENTIAL_STORED),
            WalletEventPayload::CredentialDeleted(_) => {
                EventType::new(EventType::CREDENTIAL_DELETED)
            }
            WalletEventPayload::PresentationRequestSent(_) => {
                EventType::new(EventType::PRESENTATION_REQUEST_SENT)
            }
            WalletEventPayload::PresentationRequestReceived(_) => {
                EventType::new(EventType::PRESENTATION_REQUEST_RECEIVED)
            }
            WalletEventPayload::PresentationSubmitted(_) => {
                EventType::new(EventType::PRESENTATION_SUBMITTED)
            }
            WalletEventPayload::PresentationVerified(_) => {
                EventType::new(EventType::PRESENTATION_VERIFIED)
            }
            WalletEventPayload::KeyCreated(_) => EventType::new(EventType::KEY_CREATED),
            WalletEventPayload::KeyRotated(_) => EventType::new(EventType::KEY_ROTATED),
            WalletEventPayload::KeyRevoked(_) => EventType::new(EventType::KEY_REVOKED),
        }
    }
}

// ============================================================================
// Credential Offer Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialOfferSentPayload {
    pub offer_id: String,
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<GrantsData>,
    pub credential_offer_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialOfferReceivedPayload {
    pub offer_id: String,
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<GrantsData>,
    pub credential_offer_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantsData {
    pub authorization_code: Option<AuthorizationCodeGrant>,
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PreAuthorizedCodeGrant {
    pub pre_authorized_code: String,
    pub tx_code: Option<TxCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxCode {
    pub input_mode: Option<String>,
    pub length: Option<u32>,
    pub description: Option<String>,
}

// ============================================================================
// Credential Issuance Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialIssuedPayload {
    pub credential: String, // SD-JWT VC or other format
    pub credential_type: String,
    pub notification_id: Option<String>,
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialAcknowledgedPayload {
    pub notification_id: String,
    pub event: String,
}

// ============================================================================
// Credential Storage Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialStoredPayload {
    pub credential_id: String,
    pub credential_type: String,
    pub issuer: String,
    pub notification_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialDeletedPayload {
    pub credential_id: String,
    pub notification_id: String,
    pub event: String,
}

// ============================================================================
// Presentation Request Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestSentPayload {
    pub request_id: String,
    pub dcql_query: String,
    pub nonce: String,
    pub client_id: String,
    pub response_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestReceivedPayload {
    pub request_id: String,
    pub dcql_query: String,
    pub nonce: String,
    pub client_id: String,
    pub response_uri: Option<String>,
}

// ============================================================================
// Presentation Submission Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationSubmittedPayload {
    pub request_id: String,
    pub presentation_submission_id: String,
    pub vp_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationVerifiedPayload {
    pub request_id: String,
    pub presentation_submission_id: String,
    pub validation_status: ValidationStatus,
    pub holder_binding_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStatus {
    Valid,
    Invalid { reason: String },
}

// ============================================================================
// Key Operation Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyCreatedPayload {
    pub key_id: String,
    pub kid: String,
    pub key_type: String, // "EC", "RSA", "Ed25519"
    pub key_attestation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRotatedPayload {
    pub old_key_id: String,
    pub new_key_id: String,
    pub new_kid: String,
    pub key_type: String,
    pub key_attestation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRevokedPayload {
    pub key_id: String,
    pub kid: String,
    pub revocation_reason: String,
}
