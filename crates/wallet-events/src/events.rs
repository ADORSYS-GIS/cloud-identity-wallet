use crate::traits::DomainEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Common metadata for all wallet events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMetadata {
    /// Unique identifier for this event
    pub event_id: Uuid,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
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
            timestamp: Utc::now(),
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
        self.payload.event_type()
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
            WalletEventPayload::CredentialOfferSent(_) => "CredentialOfferSent",
            WalletEventPayload::CredentialOfferReceived(_) => "CredentialOfferReceived",
            WalletEventPayload::CredentialIssued(_) => "CredentialIssued",
            WalletEventPayload::CredentialAcknowledged(_) => "CredentialAcknowledged",
            WalletEventPayload::CredentialStored(_) => "CredentialStored",
            WalletEventPayload::CredentialDeleted(_) => "CredentialDeleted",
            WalletEventPayload::PresentationRequestSent(_) => "PresentationRequestSent",
            WalletEventPayload::PresentationRequestReceived(_) => "PresentationRequestReceived",
            WalletEventPayload::PresentationSubmitted(_) => "PresentationSubmitted",
            WalletEventPayload::PresentationVerified(_) => "PresentationVerified",
            WalletEventPayload::KeyCreated(_) => "KeyCreated",
            WalletEventPayload::KeyRotated(_) => "KeyRotated",
            WalletEventPayload::KeyRevoked(_) => "KeyRevoked",
        }
    }

    pub fn event_type(&self) -> EventType {
        match self {
            WalletEventPayload::CredentialOfferSent(_) => EventType::CredentialOfferSent,
            WalletEventPayload::CredentialOfferReceived(_) => EventType::CredentialOfferReceived,
            WalletEventPayload::CredentialIssued(_) => EventType::CredentialIssued,
            WalletEventPayload::CredentialAcknowledged(_) => EventType::CredentialAcknowledged,
            WalletEventPayload::CredentialStored(_) => EventType::CredentialStored,
            WalletEventPayload::CredentialDeleted(_) => EventType::CredentialDeleted,
            WalletEventPayload::PresentationRequestSent(_) => EventType::PresentationRequestSent,
            WalletEventPayload::PresentationRequestReceived(_) => {
                EventType::PresentationRequestReceived
            }
            WalletEventPayload::PresentationSubmitted(_) => EventType::PresentationSubmitted,
            WalletEventPayload::PresentationVerified(_) => EventType::PresentationVerified,
            WalletEventPayload::KeyCreated(_) => EventType::KeyCreated,
            WalletEventPayload::KeyRotated(_) => EventType::KeyRotated,
            WalletEventPayload::KeyRevoked(_) => EventType::KeyRevoked,
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

/// Event type discriminator for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    CredentialOfferSent,
    CredentialOfferReceived,
    CredentialIssued,
    CredentialAcknowledged,
    CredentialStored,
    CredentialDeleted,
    PresentationRequestSent,
    PresentationRequestReceived,
    PresentationSubmitted,
    PresentationVerified,
    KeyCreated,
    KeyRotated,
    KeyRevoked,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::CredentialOfferSent => "CredentialOfferSent",
            EventType::CredentialOfferReceived => "CredentialOfferReceived",
            EventType::CredentialIssued => "CredentialIssued",
            EventType::CredentialAcknowledged => "CredentialAcknowledged",
            EventType::CredentialStored => "CredentialStored",
            EventType::CredentialDeleted => "CredentialDeleted",
            EventType::PresentationRequestSent => "PresentationRequestSent",
            EventType::PresentationRequestReceived => "PresentationRequestReceived",
            EventType::PresentationSubmitted => "PresentationSubmitted",
            EventType::PresentationVerified => "PresentationVerified",
            EventType::KeyCreated => "KeyCreated",
            EventType::KeyRotated => "KeyRotated",
            EventType::KeyRevoked => "KeyRevoked",
        }
    }
}

impl DomainEvent for WalletEvent {
    fn event_type(&self) -> &str {
        self.payload.event_type().as_str()
    }

    fn topic_category(&self) -> &str {
        self.payload.topic_category()
    }

    fn event_id(&self) -> String {
        self.metadata.event_id.to_string()
    }

    fn correlation_id(&self) -> String {
        self.metadata.correlation_id.clone()
    }

    fn wallet_id(&self) -> String {
        self.metadata.wallet_id.clone()
    }

    fn schema_version(&self) -> String {
        self.metadata.schema_version.clone()
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
