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

/// Main wallet event enum containing all event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event_type", content = "payload")]
pub enum WalletEvent {
    // Credential Offer Events
    CredentialOfferSent(CredentialOfferSentEvent),
    CredentialOfferReceived(CredentialOfferReceivedEvent),

    // Credential Issuance Events
    CredentialIssued(CredentialIssuedEvent),
    CredentialAcknowledged(CredentialAcknowledgedEvent),

    // Credential Storage Events
    CredentialStored(CredentialStoredEvent),
    CredentialDeleted(CredentialDeletedEvent),

    // Presentation Request Events
    PresentationRequestSent(PresentationRequestSentEvent),
    PresentationRequestReceived(PresentationRequestReceivedEvent),

    // Presentation Submission Events
    PresentationSubmitted(PresentationSubmittedEvent),
    PresentationVerified(PresentationVerifiedEvent),

    // Key Operation Events
    KeyCreated(KeyCreatedEvent),
    KeyRotated(KeyRotatedEvent),
    KeyRevoked(KeyRevokedEvent),
}

impl WalletEvent {
    pub fn metadata(&self) -> &EventMetadata {
        match self {
            WalletEvent::CredentialOfferSent(e) => &e.metadata,
            WalletEvent::CredentialOfferReceived(e) => &e.metadata,
            WalletEvent::CredentialIssued(e) => &e.metadata,
            WalletEvent::CredentialAcknowledged(e) => &e.metadata,
            WalletEvent::CredentialStored(e) => &e.metadata,
            WalletEvent::CredentialDeleted(e) => &e.metadata,
            WalletEvent::PresentationRequestSent(e) => &e.metadata,
            WalletEvent::PresentationRequestReceived(e) => &e.metadata,
            WalletEvent::PresentationSubmitted(e) => &e.metadata,
            WalletEvent::PresentationVerified(e) => &e.metadata,
            WalletEvent::KeyCreated(e) => &e.metadata,
            WalletEvent::KeyRotated(e) => &e.metadata,
            WalletEvent::KeyRevoked(e) => &e.metadata,
        }
    }

    pub fn event_type_name(&self) -> &'static str {
        match self {
            WalletEvent::CredentialOfferSent(_) => "CredentialOfferSent",
            WalletEvent::CredentialOfferReceived(_) => "CredentialOfferReceived",
            WalletEvent::CredentialIssued(_) => "CredentialIssued",
            WalletEvent::CredentialAcknowledged(_) => "CredentialAcknowledged",
            WalletEvent::CredentialStored(_) => "CredentialStored",
            WalletEvent::CredentialDeleted(_) => "CredentialDeleted",
            WalletEvent::PresentationRequestSent(_) => "PresentationRequestSent",
            WalletEvent::PresentationRequestReceived(_) => "PresentationRequestReceived",
            WalletEvent::PresentationSubmitted(_) => "PresentationSubmitted",
            WalletEvent::PresentationVerified(_) => "PresentationVerified",
            WalletEvent::KeyCreated(_) => "KeyCreated",
            WalletEvent::KeyRotated(_) => "KeyRotated",
            WalletEvent::KeyRevoked(_) => "KeyRevoked",
        }
    }
}

// ============================================================================
// Credential Offer Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialOfferSentEvent {
    pub metadata: EventMetadata,
    pub offer_id: String,
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<GrantsData>,
    pub credential_offer_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialOfferReceivedEvent {
    pub metadata: EventMetadata,
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
pub struct CredentialIssuedEvent {
    pub metadata: EventMetadata,
    pub credential: String, // SD-JWT VC or other format
    pub credential_type: String,
    pub notification_id: Option<String>,
    pub transaction_id: Option<String>
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialAcknowledgedEvent {
    pub metadata: EventMetadata,
    pub notification_id: String,
    pub event: String,
}

// ============================================================================
// Credential Storage Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialStoredEvent {
    pub metadata: EventMetadata,
    pub credential_id: String,
    pub credential_type: String,
    pub issuer: String,
    pub notification_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialDeletedEvent {
    pub metadata: EventMetadata,
    pub credential_id: String,
    pub notification_id: String,
    pub event: String, 
}

// ============================================================================
// Presentation Request Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestSentEvent {
    pub metadata: EventMetadata,
    pub request_id: String,
    pub dcql_query: String,
    pub nonce: String,
    pub client_id: String,
    pub response_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestReceivedEvent {
    pub metadata: EventMetadata,
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
pub struct PresentationSubmittedEvent {
    pub metadata: EventMetadata,
    pub request_id: String,
    pub presentation_submission_id: String,
    pub vp_token: String, 
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationVerifiedEvent {
    pub metadata: EventMetadata,
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
pub struct KeyCreatedEvent {
    pub metadata: EventMetadata,
    pub key_id: String,
    pub kid: String,
    pub key_type: String, // "EC", "RSA", "Ed25519"
    pub key_attestation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRotatedEvent {
    pub metadata: EventMetadata,
    pub old_key_id: String,
    pub new_key_id: String,
    pub new_kid: String,
    pub key_type: String,
    pub key_attestation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyRevokedEvent {
    pub metadata: EventMetadata,
    pub key_id: String,
    pub kid: String,
    pub revocation_reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_metadata_creation() {
        let metadata = EventMetadata::new("corr-123".to_string(), "wallet-456".to_string());
        
        assert_eq!(metadata.correlation_id, "corr-123");
        assert_eq!(metadata.wallet_id, "wallet-456");
        assert_eq!(metadata.schema_version, "1.0.0");
        assert!(!metadata.event_id.is_nil());
    }

    #[test]
    fn test_credential_offer_received_serialization() {
        let event = WalletEvent::CredentialOfferReceived(CredentialOfferReceivedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            offer_id: "offer-789".to_string(),
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["UniversityDegree".to_string()],
            grants: Some(GrantsData {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "code-123".to_string(),
                    tx_code: None,
                }),
            }),
            credential_offer_uri: None,
        });

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: WalletEvent = serde_json::from_str(&json).unwrap();
        
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_credential_issued_event() {
        let event = WalletEvent::CredentialIssued(CredentialIssuedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            credential: "eyJhbGc...".to_string(),
            credential_type: "UniversityDegree".to_string(),
            notification_id: Some("notif-123".to_string()),
            transaction_id: None,
        });

        assert_eq!(event.event_type_name(), "CredentialIssued");
    }

    #[test]
    fn test_presentation_verified_event() {
        let event = WalletEvent::PresentationVerified(PresentationVerifiedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            request_id: "req-123".to_string(),
            presentation_submission_id: "sub-456".to_string(),
            validation_status: ValidationStatus::Valid,
            holder_binding_verified: true,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("PresentationVerified"));
    }

    #[test]
    fn test_key_created_event() {
        let event = WalletEvent::KeyCreated(KeyCreatedEvent {
            metadata: EventMetadata::new("corr-123".to_string(), "wallet-456".to_string()),
            key_id: "key-123".to_string(),
            kid: "did:example:123#key-1".to_string(),
            key_type: "Ed25519".to_string(),
            key_attestation: Some("attestation-data".to_string()),
        });

        assert_eq!(event.event_type_name(), "KeyCreated");
    }
}
