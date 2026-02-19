//! # Audit Log Schema
use crate::traits::EventError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use uuid::Uuid;

// ============================================================================
// AuditEventType
// ============================================================================

/// All loggable protocol stages.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditEventType {
    // ── Credential Issuance (OID4VCI) ─────────────────────────────────────
    OfferSentReceived,
    TokenIssued,
    CredentialIssued,
    CredentialAcknowledged,
    DeferredCredentialPolled,

    // ── Verifiable Presentation (OID4VP) ──────────────────────────────────
    PresentationRequestReceived,
    PresentationSubmitted,
    PresentationVerified,

    // ── Key and Security Operations ────────────────────────────────────────
    KeyProofValidated,
    AttestationVerified,
    KeyOperation,

    // ── Catch-all ─────────────────────────────────────────────────────────
    Custom(String),
}

impl AuditEventType {
    // Event-type strings for the protocol stages that are exclusive to the
    // audit layer (not part of the core EventType constants in events.rs).
    pub const TOKEN_ISSUED: &str = "token.issued";
    pub const KEY_PROOF_VALIDATED: &str = "key.proof.validated";
    pub const ATTESTATION_VERIFIED: &str = "attestation.verified";
    pub const DEFERRED_CREDENTIAL_POLLED: &str = "credential.deferred.polled";

    /// Returns a stable string representation suitable for storage / querying.
    pub fn as_str(&self) -> &str {
        match self {
            Self::OfferSentReceived => "OFFER_SENT_RECEIVED",
            Self::TokenIssued => "TOKEN_ISSUED",
            Self::CredentialIssued => "CREDENTIAL_ISSUED",
            Self::CredentialAcknowledged => "CREDENTIAL_ACKNOWLEDGED",
            Self::DeferredCredentialPolled => "DEFERRED_CREDENTIAL_POLLED",
            Self::PresentationRequestReceived => "PRESENTATION_REQUEST_RECEIVED",
            Self::PresentationSubmitted => "PRESENTATION_SUBMITTED",
            Self::PresentationVerified => "PRESENTATION_VERIFIED",
            Self::KeyProofValidated => "KEY_PROOF_VALIDATED",
            Self::AttestationVerified => "ATTESTATION_VERIFIED",
            Self::KeyOperation => "KEY_OPERATION",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Derive the audit event type from a raw event-type string produced by
    /// [`crate::events::EventType`].
    pub fn from_event_type_str(s: &str) -> Self {
        match s {
            "credential.offer.sent" | "credential.offer.received" => Self::OfferSentReceived,
            "token.issued" => Self::TokenIssued,
            "credential.issued" => Self::CredentialIssued,
            "credential.acknowledged" | "credential.deleted" => Self::CredentialAcknowledged,
            "credential.deferred.polled" => Self::DeferredCredentialPolled,
            "presentation.request.received" | "presentation.request.sent" => {
                Self::PresentationRequestReceived
            }
            "presentation.submitted" => Self::PresentationSubmitted,
            "presentation.verified" => Self::PresentationVerified,
            "key.proof.validated" => Self::KeyProofValidated,
            "attestation.verified" => Self::AttestationVerified,
            "key.created" | "key.rotated" | "key.revoked" => Self::KeyOperation,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// AuditStatus
// ============================================================================

/// Outcome of the audited operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum AuditStatus {
    Success,
    Pending,
    Failure { reason: String },
}

// ============================================================================
// CorrelationIds
// ============================================================================

/// OID4VCI / OID4VP correlation identifiers that link related protocol steps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationIds {
    /// Links the initial credential request to deferred-issuance completion.
    pub transaction_id: Option<String>,
    /// Tracks credential storage / deletion acknowledgment lifecycle.
    pub notification_id: Option<String>,
    /// Links a verifier's presentation request to the wallet's response.
    pub nonce: Option<String>,
    /// Identifier of the Wallet or Verifier client
    pub client_id: Option<String>,
    /// Short-lived per-session UUID used in anonymous flows instead of a
    /// permanent identifier.
    pub session_token: Option<Uuid>,
}

impl CorrelationIds {
    /// Returns `true` when this is an anonymous flow (no `client_id`).
    pub fn is_anonymous(&self) -> bool {
        self.client_id.is_none()
    }
}

// ============================================================================
// AuditLogEntry
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub log_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub event_type: AuditEventType,
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub correlation: CorrelationIds,
    pub status: AuditStatus,
    pub wallet_id: String,
    pub extra: HashMap<String, Value>,
}

impl AuditLogEntry {
    /// Create a new [`AuditLogEntry`] with a generated log ID and the current
    /// UTC timestamp.
    pub fn new(
        event_type: AuditEventType,
        wallet_id: impl Into<String>,
        status: AuditStatus,
    ) -> Self {
        Self {
            log_id: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
            event_type,
            subject: None,
            client_id: None,
            correlation: CorrelationIds::default(),
            status,
            wallet_id: wallet_id.into(),
            extra: HashMap::new(),
        }
    }

    /// Set the opaque subject identifier (e.g. token `sub` claim).
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the client identifier.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Attach correlation identifiers.
    pub fn with_correlation(mut self, correlation: CorrelationIds) -> Self {
        self.correlation = correlation;
        self
    }

    /// Add a single privacy-safe metadata key-value pair.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

// ============================================================================
// AuditQuery
// ============================================================================

/// Filter criteria for querying stored audit log entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Filter to a specific subject identifier.
    pub subject: Option<String>,
    /// Filter to a specific wallet instance.
    pub wallet_id: Option<String>,
    /// Filter to a specific audit event type.
    pub event_type: Option<AuditEventType>,
    /// Only return entries at or after this time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    /// Only return entries at or before this time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    /// Maximum number of entries to return.
    pub limit: Option<usize>,
}

impl AuditQuery {
    /// Returns `true` if `entry` matches all set filter criteria.
    pub fn matches(&self, entry: &AuditLogEntry) -> bool {
        if let Some(ref s) = self.subject
            && entry.subject.as_deref() != Some(s.as_str())
        {
            return false;
        }
        if let Some(ref wid) = self.wallet_id
            && &entry.wallet_id != wid
        {
            return false;
        }
        if let Some(ref et) = self.event_type
            && &entry.event_type != et
        {
            return false;
        }
        if let Some(from) = self.from
            && entry.timestamp < from
        {
            return false;
        }
        if let Some(to) = self.to
            && entry.timestamp > to
        {
            return false;
        }
        true
    }
}

// ============================================================================
// AuditStore trait
// ===========================================================================
#[async_trait]
pub trait AuditStore: Send + Sync {
    /// Append a new entry to the audit log.
    async fn append(&self, entry: &AuditLogEntry) -> Result<(), EventError>;

    /// Query stored entries matching the given filter.
    async fn query(&self, filter: &AuditQuery) -> Result<Vec<AuditLogEntry>, EventError>;

    /// Return the total number of stored entries.
    async fn count(&self) -> Result<usize, EventError>;
}

// ============================================================================
// InMemoryAuditStore
// ============================================================================
#[derive(Debug, Default, Clone)]
pub struct InMemoryAuditStore {
    entries: Arc<Mutex<Vec<AuditLogEntry>>>,
}

impl InMemoryAuditStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a snapshot of all stored entries (for test assertions).
    pub fn snapshot(&self) -> Vec<AuditLogEntry> {
        self.entries
            .lock()
            .expect("InMemoryAuditStore lock poisoned")
            .clone()
    }
}

#[async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn append(&self, entry: &AuditLogEntry) -> Result<(), EventError> {
        self.entries
            .lock()
            .map_err(|e| {
                EventError::HandlerError(format!("InMemoryAuditStore lock poisoned: {e}"))
            })?
            .push(entry.clone());
        Ok(())
    }

    async fn query(&self, filter: &AuditQuery) -> Result<Vec<AuditLogEntry>, EventError> {
        let entries = self
            .entries
            .lock()
            .map_err(|e| {
                EventError::HandlerError(format!("InMemoryAuditStore lock poisoned: {e}"))
            })?
            .clone();

        let mut results: Vec<AuditLogEntry> =
            entries.into_iter().filter(|e| filter.matches(e)).collect();

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    async fn count(&self) -> Result<usize, EventError> {
        Ok(self
            .entries
            .lock()
            .map_err(|e| {
                EventError::HandlerError(format!("InMemoryAuditStore lock poisoned: {e}"))
            })?
            .len())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(event_type: AuditEventType) -> AuditLogEntry {
        AuditLogEntry::new(event_type, "wallet-test", AuditStatus::Success)
    }

    // ── Schema construction ────────────────────────────────────────────────

    #[test]
    fn new_entry_has_generated_log_id_and_timestamp() {
        let entry = sample_entry(AuditEventType::CredentialIssued);
        // log_id must be a non-nil UUID
        assert_ne!(entry.log_id, Uuid::nil());
        // timestamp must be close to now
        let now = OffsetDateTime::now_utc();
        let delta = now - entry.timestamp;
        assert!(delta.whole_seconds() < 2, "timestamp should be recent");
    }

    #[test]
    fn builder_methods_set_fields() {
        let cids = CorrelationIds {
            transaction_id: Some("txn-1".into()),
            notification_id: Some("notif-1".into()),
            nonce: Some("abc123".into()),
            client_id: None,
            session_token: Some(Uuid::new_v4()),
        };

        let entry = sample_entry(AuditEventType::CredentialAcknowledged)
            .with_subject("did:example:123")
            .with_client_id("wallet-client-1")
            .with_correlation(cids.clone())
            .with_extra("credential_type", "VerifiableID");

        assert_eq!(entry.subject.as_deref(), Some("did:example:123"));
        assert_eq!(entry.client_id.as_deref(), Some("wallet-client-1"));
        assert_eq!(entry.correlation.transaction_id.as_deref(), Some("txn-1"));
        assert_eq!(
            entry.extra.get("credential_type").and_then(|v| v.as_str()),
            Some("VerifiableID")
        );
    }

    // ── Privacy guarantees ─────────────────────────────────────────────────

    #[test]
    fn serialized_entry_does_not_contain_raw_credential_bytes() {
        // Simulate an issuance entry: only opaque IDs, no signed material.
        let entry = sample_entry(AuditEventType::CredentialIssued)
            .with_extra("credential_type", "UniversityDegree");

        let json = serde_json::to_string(&entry).expect("serialize");

        // The JSON must NOT contain any fake "credential" raw bytes marker.
        assert!(
            !json.contains("eyJhbGciOiJFUzI1NiJ9"), // JWT-like prefix
            "Raw credential bytes must not appear in audit log JSON"
        );
    }

    #[test]
    fn anonymous_flow_has_no_subject_or_client_id() {
        let entry = AuditLogEntry::new(
            AuditEventType::PresentationSubmitted,
            "wallet-anon",
            AuditStatus::Success,
        )
        .with_correlation(CorrelationIds {
            session_token: Some(Uuid::new_v4()),
            ..Default::default()
        });

        assert!(entry.subject.is_none(), "anonymous: subject must be None");
        assert!(
            entry.client_id.is_none(),
            "anonymous: client_id must be None"
        );
        assert!(entry.correlation.is_anonymous());
    }

    // ── AuditEventType round-trip ──────────────────────────────────────────

    #[test]
    fn audit_event_type_serde_round_trip() {
        let types = [
            AuditEventType::OfferSentReceived,
            AuditEventType::TokenIssued,
            AuditEventType::CredentialIssued,
            AuditEventType::CredentialAcknowledged,
            AuditEventType::DeferredCredentialPolled,
            AuditEventType::PresentationRequestReceived,
            AuditEventType::PresentationSubmitted,
            AuditEventType::PresentationVerified,
            AuditEventType::KeyProofValidated,
            AuditEventType::AttestationVerified,
            AuditEventType::KeyOperation,
            AuditEventType::Custom("my.custom.event".into()),
        ];

        for et in &types {
            let json = serde_json::to_string(et).expect("serialize");
            let back: AuditEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(et, &back, "round-trip failed for {et}");
        }
    }

    #[test]
    fn from_event_type_str_maps_known_strings() {
        assert_eq!(
            AuditEventType::from_event_type_str("credential.offer.sent"),
            AuditEventType::OfferSentReceived
        );
        assert_eq!(
            AuditEventType::from_event_type_str("key.proof.validated"),
            AuditEventType::KeyProofValidated
        );
        assert_eq!(
            AuditEventType::from_event_type_str("unknown.event"),
            AuditEventType::Custom("unknown.event".into())
        );
    }

    // ── CorrelationIds ─────────────────────────────────────────────────────

    #[test]
    fn all_none_correlation_ids_serialize_without_panic() {
        let cids = CorrelationIds::default();
        let json = serde_json::to_string(&cids).expect("serialize");
        // all fields null / missing
        let v: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
        assert!(v["transaction_id"].is_null());
        assert!(v["client_id"].is_null());
        assert!(cids.is_anonymous());
    }

    // ── AuditQuery matching ────────────────────────────────────────────────

    #[tokio::test]
    async fn in_memory_store_append_and_query() {
        let store = InMemoryAuditStore::new();

        let e1 = sample_entry(AuditEventType::CredentialIssued)
            .with_subject("sub-1")
            .with_extra("credential_type", "PID");
        let e2 = sample_entry(AuditEventType::PresentationSubmitted).with_subject("sub-2");

        store.append(&e1).await.expect("append e1");
        store.append(&e2).await.expect("append e2");

        assert_eq!(store.count().await.unwrap(), 2);

        // Filter by event type
        let results = store
            .query(&AuditQuery {
                event_type: Some(AuditEventType::CredentialIssued),
                ..Default::default()
            })
            .await
            .expect("query");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_type, AuditEventType::CredentialIssued);
    }

    #[tokio::test]
    async fn in_memory_store_limit() {
        let store = InMemoryAuditStore::new();

        for _ in 0..5 {
            store
                .append(&sample_entry(AuditEventType::KeyOperation))
                .await
                .expect("append");
        }

        let results = store
            .query(&AuditQuery {
                limit: Some(2),
                ..Default::default()
            })
            .await
            .expect("query");

        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn in_memory_store_filter_by_subject() {
        let store = InMemoryAuditStore::new();

        store
            .append(&sample_entry(AuditEventType::TokenIssued).with_subject("alice"))
            .await
            .expect("append");
        store
            .append(&sample_entry(AuditEventType::TokenIssued).with_subject("bob"))
            .await
            .expect("append");

        let results = store
            .query(&AuditQuery {
                subject: Some("alice".into()),
                ..Default::default()
            })
            .await
            .expect("query");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject.as_deref(), Some("alice"));
    }
}
