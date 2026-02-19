//! # Event Logger
use crate::{
    audit_log::{AuditEventType, AuditLogEntry, AuditStatus, AuditStore, CorrelationIds},
    events::Event,
    traits::{EventError, Handler},
};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

// ============================================================================
// EventLogger
// ============================================================================
pub struct EventLogger {
    store: Arc<dyn AuditStore>,
}

impl EventLogger {
    /// Create a new logger backed by the given [`AuditStore`].
    pub fn new(store: Arc<dyn AuditStore>) -> Self {
        Self { store }
    }

    /// Build an [`AuditLogEntry`] from a raw [`Event`]
    pub(crate) fn map_event(event: &Event) -> AuditLogEntry {
        let event_type = AuditEventType::from_event_type_str(event.event_type.as_str());

        // ── Privacy filter ─────────────────────────────────────────────────
        // Extracting only explicitly allowlisted metadata keys.
        let subject = Self::extract_safe_string(&event.metadata, "subject");
        let wallet_id = Self::extract_safe_string(&event.metadata, "wallet_id")
            .unwrap_or_else(|| "unknown".to_string());

        // client_id from metadata; absent → anonymous flow
        let client_id = Self::extract_safe_string(&event.metadata, "client_id");
        let inner_payload = event.payload.get("payload").and_then(|v| v.as_object());
        // look in metadata first, then top-level payload, then nested payload.
        let extract_corr = |key: &str| -> Option<String> {
            Self::extract_safe_string(&event.metadata, key)
                .or_else(|| {
                    event
                        .payload
                        .get(key)
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .or_else(|| {
                    inner_payload
                        .and_then(|p| p.get(key))
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
        };

        let transaction_id = extract_corr("transaction_id");
        let notification_id = extract_corr("notification_id");
        let nonce = extract_corr("nonce");

        let session_token: Option<Uuid> = if client_id.is_none() {
            // derive a session token from the event's own ID
            // so within-transaction entries share the same session UUID.
            Self::extract_safe_string(&event.metadata, "session_token")
                .and_then(|s| s.parse::<Uuid>().ok())
                .or(Some(event.id))
        } else {
            None
        };

        let correlation = CorrelationIds {
            transaction_id,
            notification_id,
            nonce,
            client_id: client_id.clone(),
            session_token,
        };

        // ── Status mapping ─────────────────────────────────────────────────
        let status = Self::derive_status(&event.metadata);

        // ── Safe extra metadata ────────────────────────────────────────────
        // Only the allowlisted keys below are forwarded; all other payload
        // content is dropped here to prevent accidental PII logging.
        let safe_keys = [
            "credential_type",
            "key_type",
            "key_id",
            "kid",
            "credential_id",
            "credential_issuer",
            "request_id",
            "category",
            "correlation_id",
            "holder_binding_verified",
        ];

        let mut entry = AuditLogEntry::new(event_type, wallet_id, status);

        if let Some(sub) = subject {
            entry = entry.with_subject(sub);
        }
        if let Some(cid) = client_id {
            entry = entry.with_client_id(cid);
        }
        entry = entry.with_correlation(correlation);

        // Scan metadata, then top-level payload object, then nested payload.
        for key in &safe_keys {
            if let Some(v) = event.metadata.get(*key)
                && !v.is_null()
            {
                entry = entry.with_extra(*key, v.clone());
                continue;
            }
            if let Some(v) = event.payload.get(*key)
                && !v.is_null()
            {
                entry = entry.with_extra(*key, v.clone());
                continue;
            }
            if let Some(nested) = inner_payload
                && let Some(v) = nested.get(*key)
                && !v.is_null()
            {
                entry = entry.with_extra(*key, v.clone());
            }
        }

        entry
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// Extract a `String` value from a metadata map by key.
    fn extract_safe_string(
        metadata: &std::collections::HashMap<String, Value>,
        key: &str,
    ) -> Option<String> {
        metadata.get(key)?.as_str().map(str::to_string)
    }

    /// Derive an [`AuditStatus`] from the event metadata.
    fn derive_status(metadata: &std::collections::HashMap<String, Value>) -> AuditStatus {
        match metadata
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("success")
        {
            "pending" | "issuance_pending" | "deferred" => AuditStatus::Pending,
            s if s.starts_with("error") || s.starts_with("fail") || s.starts_with("invalid") => {
                AuditStatus::Failure {
                    reason: s.to_string(),
                }
            }
            _ => AuditStatus::Success,
        }
    }
}

#[async_trait]
impl Handler for EventLogger {
    async fn handle(&self, event: &Event) -> Result<(), EventError> {
        let entry = Self::map_event(event);

        debug!(
            log_id = %entry.log_id,
            event_type = %entry.event_type,
            wallet_id = %entry.wallet_id,
            status = ?entry.status,
            "Writing audit log entry"
        );

        self.store.append(&entry).await.map_err(|e| {
            warn!(error = %e, "Failed to write audit log entry");
            e
        })
    }

    fn name(&self) -> &'static str {
        "EventLogger"
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit_log::{AuditQuery, AuditStatus, InMemoryAuditStore},
        events::{Event, EventType, WalletEvent, WalletEventPayload},
    };
    use serde_json::json;
    use std::sync::Arc;

    // ── Helpers ────────────────────────────────────────────────────────────

    fn make_store() -> Arc<InMemoryAuditStore> {
        Arc::new(InMemoryAuditStore::new())
    }

    fn logger_with_store(store: Arc<InMemoryAuditStore>) -> EventLogger {
        EventLogger::new(store)
    }

    fn credential_issued_event() -> Event {
        let payload =
            WalletEventPayload::CredentialIssued(crate::events::CredentialIssuedPayload {
                credential: "REDACTED_CREDENTIAL_BYTES".to_string(), // intentionally opaque
                credential_type: "UniversityDegree".to_string(),
                notification_id: Some("notif-42".to_string()),
                transaction_id: Some("txn-99".to_string()),
            });
        let wallet_event = WalletEvent::new(
            "corr-abc".to_string(),
            "wallet-unit-test".to_string(),
            payload,
        );
        wallet_event
            .try_into()
            .expect("Failed to convert WalletEvent → Event")
    }

    fn anonymous_presentation_event() -> Event {
        // No client_id in metadata → anonymous
        Event::new(
            EventType::new("presentation.submitted"),
            json!({"request_id": "req-1", "vp_token": "REDACTED_VP_TOKEN"}),
        )
        .with_metadata("wallet_id", "wallet-anon")
        .with_metadata("nonce", "nonce-xyz")
        // Deliberately NOT setting client_id or subject
    }

    // ── Mapping tests (sync, no store needed) ──────────────────────────────

    #[test]
    fn map_credential_issued_event_extracts_safe_fields() {
        let event = credential_issued_event();
        let entry = EventLogger::map_event(&event);

        assert_eq!(entry.event_type, AuditEventType::CredentialIssued);
        assert_eq!(entry.wallet_id, "wallet-unit-test");
        // notification_id and transaction_id come from the payload
        assert_eq!(
            entry.correlation.notification_id.as_deref(),
            Some("notif-42")
        );
        assert_eq!(entry.correlation.transaction_id.as_deref(), Some("txn-99"));
    }

    #[test]
    fn map_event_does_not_store_raw_credential_bytes() {
        let event = credential_issued_event();
        let entry = EventLogger::map_event(&event);

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("REDACTED_CREDENTIAL_BYTES"),
            "Raw credential bytes must not appear in AuditLogEntry JSON"
        );
    }

    #[test]
    fn map_event_does_not_store_raw_vp_token() {
        let event = anonymous_presentation_event();
        let entry = EventLogger::map_event(&event);

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("REDACTED_VP_TOKEN"),
            "VP token must not appear in AuditLogEntry JSON"
        );
    }

    #[test]
    fn anonymous_flow_leaves_subject_and_client_id_none() {
        let event = anonymous_presentation_event();
        let entry = EventLogger::map_event(&event);

        assert!(
            entry.subject.is_none(),
            "anonymous flow: subject must be None"
        );
        assert!(
            entry.client_id.is_none(),
            "anonymous flow: client_id must be None"
        );
        assert!(
            entry.correlation.is_anonymous(),
            "anonymous flow: correlation must be anonymous"
        );
        // Session token should be set for within-transaction linking
        assert!(
            entry.correlation.session_token.is_some(),
            "anonymous flow: session_token must be set"
        );
    }

    #[test]
    fn identified_flow_captures_subject_and_client_id() {
        let event = Event::new(
            EventType::new("token.issued"),
            json!({"credential_type": "PID"}),
        )
        .with_metadata("wallet_id", "wallet-1")
        .with_metadata("subject", "did:example:alice")
        .with_metadata("client_id", "verifier-app-x");

        let entry = EventLogger::map_event(&event);

        assert_eq!(entry.subject.as_deref(), Some("did:example:alice"));
        assert_eq!(entry.client_id.as_deref(), Some("verifier-app-x"));
        assert!(
            entry.correlation.session_token.is_none(),
            "identified flow must not set session_token"
        );
    }

    #[test]
    fn status_mapping_from_metadata() {
        let mut event = Event::new(EventType::new("credential.issued"), json!(null));
        event.metadata.insert("wallet_id".into(), json!("w1"));

        // Pending
        event
            .metadata
            .insert("status".into(), json!("issuance_pending"));
        let entry = EventLogger::map_event(&event);
        assert_eq!(entry.status, AuditStatus::Pending);

        // Failure
        event
            .metadata
            .insert("status".into(), json!("invalid_proof"));
        let entry = EventLogger::map_event(&event);
        assert!(matches!(entry.status, AuditStatus::Failure { .. }));

        // Success (default)
        event.metadata.remove("status");
        let entry = EventLogger::map_event(&event);
        assert_eq!(entry.status, AuditStatus::Success);
    }

    #[test]
    fn unknown_event_type_maps_to_custom() {
        let event = Event::new(EventType::new("some.completely.unknown.event"), json!(null))
            .with_metadata("wallet_id", "w1");

        let entry = EventLogger::map_event(&event);
        assert_eq!(
            entry.event_type,
            AuditEventType::Custom("some.completely.unknown.event".into())
        );
    }

    // ── Integration: EventLogger + InMemoryAuditStore ──────────────────────

    #[tokio::test]
    async fn handle_writes_entry_to_store() {
        let store = make_store();
        let logger = logger_with_store(store.clone());

        let event = credential_issued_event();
        logger.handle(&event).await.expect("handle");

        assert_eq!(store.count().await.unwrap(), 1);
        let entries = store.snapshot();
        assert_eq!(entries[0].event_type, AuditEventType::CredentialIssued);
    }

    #[tokio::test]
    async fn handle_multiple_events_queryable_by_type() {
        let store = make_store();
        let logger = logger_with_store(store.clone());

        // Two different event types
        logger
            .handle(&credential_issued_event())
            .await
            .expect("handle 1");
        logger
            .handle(&anonymous_presentation_event())
            .await
            .expect("handle 2");

        assert_eq!(store.count().await.unwrap(), 2);

        let issuance_entries = store
            .query(&AuditQuery {
                event_type: Some(AuditEventType::CredentialIssued),
                ..Default::default()
            })
            .await
            .expect("query");

        assert_eq!(issuance_entries.len(), 1);
    }

    #[tokio::test]
    async fn handle_anonymous_event_stores_session_token() {
        let store = make_store();
        let logger = logger_with_store(store.clone());

        logger
            .handle(&anonymous_presentation_event())
            .await
            .expect("handle");

        let entry = &store.snapshot()[0];
        assert!(entry.correlation.session_token.is_some());
        assert!(entry.subject.is_none());
    }

    #[test]
    fn logger_name_is_event_logger() {
        let store = make_store();
        let logger = EventLogger::new(store);
        assert_eq!(logger.name(), "EventLogger");
    }
}
