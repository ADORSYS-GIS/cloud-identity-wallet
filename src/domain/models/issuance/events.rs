use std::borrow::Cow;

use axum::response::sse::Event as SseEvent;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Represents the step in the issuance flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceStep {
    OfferResolution,
    Metadata,
    Authorization,
    Token,
    CredentialRequest,
    DeferredCredential,
    Notification,
    Internal,
}

impl IssuanceStep {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfferResolution => "offer_resolution",
            Self::Metadata => "metadata",
            Self::Authorization => "authorization",
            Self::Token => "token",
            Self::CredentialRequest => "credential_request",
            Self::DeferredCredential => "deferred_credential",
            Self::Notification => "notification",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for IssuanceStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A processing event emitted while the server is performing back-channel
/// operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseProcessingEvent {
    pub session_id: String,
    pub state: ProcessingState,
    pub step: ProcessingStep,
}

impl SseProcessingEvent {
    pub fn new(session_id: impl Into<String>, step: ProcessingStep) -> Self {
        let session_id: String = session_id.into();
        debug!(session_id = %session_id, ?step, "emitting processing event");
        Self {
            session_id,
            state: ProcessingState::Processing,
            step,
        }
    }

    /// Convert to an SSE event frame.
    pub fn to_sse_event(&self) -> Result<SseEvent, axum::Error> {
        SseEvent::default().event("processing").json_data(self)
    }
}

/// The specific back-channel operation in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingStep {
    /// Exchanging authorization/pre-authorized code for an access token.
    ExchangingToken,
    /// Calling the issuer's credential endpoint.
    RequestingCredential,
    /// Credential issuance is deferred; backend is polling.
    AwaitingDeferredCredential,
}

impl ProcessingStep {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExchangingToken => "exchanging_token",
            Self::RequestingCredential => "requesting_credential",
            Self::AwaitingDeferredCredential => "awaiting_deferred_credential",
        }
    }
}

impl std::fmt::Display for ProcessingStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<IssuanceStep> for ProcessingStep {
    fn from(step: IssuanceStep) -> Self {
        match step {
            IssuanceStep::Token => Self::ExchangingToken,
            IssuanceStep::CredentialRequest => Self::RequestingCredential,
            IssuanceStep::DeferredCredential => Self::AwaitingDeferredCredential,
            _ => Self::ExchangingToken,
        }
    }
}

/// Always `"processing"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingState {
    Processing,
}

/// A completed event, terminal success. Credentials were issued and stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseCompletedEvent {
    pub session_id: String,
    pub state: CompletedState,
    /// Internal wallet credential IDs (UUID) for the issued credentials.
    pub credential_ids: Vec<String>,
    /// `credential_configuration_id` values of the issued credentials.
    pub credential_types: Vec<String>,
}

impl SseCompletedEvent {
    pub fn new(
        session_id: impl Into<String>,
        credential_ids: impl Into<Vec<String>>,
        credential_types: impl Into<Vec<String>>,
    ) -> Self {
        let session_id: String = session_id.into();
        Self {
            session_id: session_id.clone(),
            state: CompletedState::Completed,
            credential_ids: credential_ids.into(),
            credential_types: credential_types.into(),
        }
    }

    /// Convert to an SSE event frame.
    pub fn to_sse_event(&self) -> Result<SseEvent, axum::Error> {
        SseEvent::default().event("completed").json_data(self)
    }
}

/// Always `"completed"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletedState {
    Completed,
}

/// A failed event, terminal error. The session is discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseFailedEvent {
    pub session_id: String,
    pub state: FailedState,
    pub error: Cow<'static, str>,
    pub error_description: Option<String>,
    /// The phase at which the failure occurred.
    pub step: IssuanceStep,
}

impl SseFailedEvent {
    pub fn new(
        session_id: impl Into<String>,
        error: impl Into<Cow<'static, str>>,
        error_description: Option<String>,
        step: IssuanceStep,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            state: FailedState::Failed,
            error: error.into(),
            error_description,
            step,
        }
    }

    /// Convert to an SSE event frame.
    pub fn to_sse_event(&self) -> Result<SseEvent, axum::Error> {
        SseEvent::default().event("failed").json_data(self)
    }
}

/// Always `"failed"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedState {
    Failed,
}

/// SSE events. Used as the payload sent through the SSE event dispatcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum IssuanceEvent {
    Processing(SseProcessingEvent),
    Completed(SseCompletedEvent),
    Failed(SseFailedEvent),
}

impl IssuanceEvent {
    /// Returns the session ID for this event.
    pub fn session_id(&self) -> &str {
        match self {
            Self::Processing(e) => &e.session_id,
            Self::Completed(e) => &e.session_id,
            Self::Failed(e) => &e.session_id,
        }
    }

    /// Returns `true` if this is a terminal event (completed or failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed(_) | Self::Failed(_))
    }

    /// Convert to an SSE event frame.
    pub fn to_sse_event(&self) -> Result<SseEvent, axum::Error> {
        match self {
            Self::Processing(e) => e.to_sse_event(),
            Self::Completed(e) => e.to_sse_event(),
            Self::Failed(e) => e.to_sse_event(),
        }
    }

    /// Serialize to a JSON vector for transport.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from a JSON vector.
    pub fn from_json(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processing_event_serializes_correctly() {
        let event = SseProcessingEvent::new("ses_test", ProcessingStep::ExchangingToken);
        let json = serde_json::to_value(&event).unwrap();
        let expected = serde_json::json!({
            "session_id": "ses_test",
            "state": "exchanging_token",
            "step": "processing"
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn completed_event_serializes_correctly() {
        let event = SseCompletedEvent::new(
            "ses_test",
            vec!["uuid-1".into()],
            vec!["eu.europa.ec.eudi.pid.1".into()],
        );
        let json = serde_json::to_value(&event).unwrap();
        let expected = serde_json::json!({
            "session_id": "ses_test",
            "state": "completed",
            "credential_ids": ["uuid-1"],
            "credential_types": ["eu.europa.ec.eudi.pid.1"]
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn failed_event_serializes_correctly() {
        let event = SseFailedEvent::new(
            "ses_test",
            "access_denied",
            Some("User denied authorization".into()),
            IssuanceStep::Authorization,
        );
        let json = serde_json::to_value(&event).unwrap();
        let expected = serde_json::json!({
            "session_id": "ses_test",
            "state": "failed",
            "error": "access_denied",
            "error_description": "User denied authorization",
            "step": "authorization"
        });
        assert_eq!(json, expected);
    }

    #[test]
    fn issuance_event_round_trip_json() {
        let event = IssuanceEvent::Processing(SseProcessingEvent::new(
            "ses_123",
            ProcessingStep::RequestingCredential,
        ));
        let json = event.to_json().unwrap();
        let parsed = IssuanceEvent::from_json(&json).unwrap();
        assert_eq!(parsed.session_id(), "ses_123");
        assert!(matches!(parsed, IssuanceEvent::Processing(_)));
    }

    #[test]
    fn terminal_event_detection() {
        let processing = IssuanceEvent::Processing(SseProcessingEvent::new(
            "ses",
            ProcessingStep::ExchangingToken,
        ));
        assert!(!processing.is_terminal());

        let completed = IssuanceEvent::Completed(SseCompletedEvent::new("ses", vec![], vec![]));
        assert!(completed.is_terminal());

        let failed = IssuanceEvent::Failed(SseFailedEvent::new(
            "ses",
            "err",
            None,
            IssuanceStep::Internal,
        ));
        assert!(failed.is_terminal());
    }

    #[test]
    fn sse_event_frame_serialization() {
        let event = SseProcessingEvent::new("ses", ProcessingStep::ExchangingToken);
        let _axum_event = event.to_sse_event().unwrap();
        let json = serde_json::to_value(&event).unwrap();
        let expected = serde_json::json!({
            "event": "processing",
            "data": {
                "session_id": "ses",
                "state": "processing",
                "step": "exchanging_token"
            }
        });
        assert_eq!(json, expected);
    }
}
