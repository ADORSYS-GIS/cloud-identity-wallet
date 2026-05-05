//! SSE handler for issuance session events.

use std::pin::Pin;
use std::time::Duration;

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, KeepAliveStream, Sse},
};
use futures::stream::{Stream, StreamExt};
use time::UtcDateTime;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::domain::models::issuance::{
    IssuanceEvent, IssuanceStep, SseCompletedEvent, SseFailedEvent,
};
use crate::domain::ports::IssuanceEventStream;
use crate::server::error::ApiError;
use crate::server::AppState;
use crate::session::{IssuanceSession, IssuanceState, SessionStore};

type SseBody = Sse<KeepAliveStream<Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>>>>;

/// GET /api/v1/issuance/{session_id}/events
///
/// Server-Sent Events stream for real-time session state updates.
/// Returns 404 for unknown/expired sessions or tenant mismatch.
pub async fn get_session_events<S: SessionStore>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Extension(tenant_id): Extension<Uuid>,
) -> Result<SseBody, ApiError> {
    debug!(session_id = %session_id, tenant_id = %tenant_id, "SSE connection request");

    let session: IssuanceSession = state
        .service
        .session
        .get(session_id.as_str())
        .await
        .map_err(|e| ApiError::internal(e))?
        .ok_or_else(|| ApiError {
            status: StatusCode::NOT_FOUND,
            error: "session_not_found".into(),
            error_description: Some("Session not found or has expired.".into()),
        })?;

    if session.tenant_id != tenant_id {
        warn!(
            session_id = %session_id,
            tenant_id = %tenant_id,
            session_tenant_id = %session.tenant_id,
            "Tenant mismatch"
        );
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            error: "session_not_found".into(),
            error_description: Some("Session not found or has expired.".into()),
        });
    }

    if session.state.is_terminal() {
        debug!(session_id = %session_id, state = ?session.state, "Session in terminal state");
        return Ok(emit_terminal_event(&session));
    }

    let stream = state
        .service
        .event_subscriber
        .subscribe(&session_id)
        .await
        .map_err(|e| ApiError::internal(e))?;

    Ok(build_sse_stream(stream))
}

fn emit_terminal_event(session: &IssuanceSession) -> SseBody {
    use futures::stream;

    let event = match session.state {
        IssuanceState::Completed => IssuanceEvent::Completed(SseCompletedEvent::new(
            &session.id,
            vec![],
            vec![],
        )),
        IssuanceState::Failed => IssuanceEvent::Failed(SseFailedEvent::new(
            &session.id,
            "session_terminated",
            Some("Session has terminated.".into()),
            IssuanceStep::Internal,
        )),
        _ => IssuanceEvent::Failed(SseFailedEvent::new(
            &session.id,
            "invalid_state",
            Some("Session is in an invalid state.".into()),
            IssuanceStep::Internal,
        )),
    };

    let stream = stream::iter(vec![Ok(event)]);
    let mapped = stream.map(|ev| ev.and_then(|e| e.to_sse_event()));
    let boxed: Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>> = Box::pin(mapped);
    Sse::new(boxed).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

fn build_sse_stream(stream: IssuanceEventStream) -> SseBody {
    let sse_stream = stream.map(|event| {
        let is_terminal = event.is_terminal();
        debug!(session_id = %event.session_id(), is_terminal, "Emitting SSE event");

        let sse_event = event
            .to_sse_event()
            .map(|e| e.id(UtcDateTime::now().unix_timestamp_nanos().to_string()));

        if is_terminal {
            debug!(session_id = %event.session_id(), "Terminal event, stream closing");
        }

        sse_event
    });

    let boxed: Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>> = Box::pin(sse_stream);
    Sse::new(boxed).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::issuance::FlowType;
    use crate::domain::ports::IssuanceEventSubscriber;
    use async_trait::async_trait;
    use cloud_wallet_openid4vc::issuance::client::ResolvedOfferContext;
    use futures::stream;

    fn create_test_session(tenant_id: Uuid, state: IssuanceState) -> IssuanceSession {
        let context: ResolvedOfferContext = serde_json::from_value(serde_json::json!({
            "offer": {
                "credential_issuer": "https://issuer.example.com",
                "credential_configuration_ids": ["test_credential"],
                "grants": { "authorization_code": { "issuer_state": "test_state" } }
            },
            "issuer_metadata": {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "credential_configurations_supported": {
                    "test_credential": { "format": "dc+sd-jwt", "vct": "https://credentials.example.com/test" }
                }
            },
            "as_metadata": {
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "response_types_supported": ["code"]
            },
            "flow": { "AuthorizationCode": { "issuer_state": "test_state" } }
        }))
        .unwrap();

        let mut session = IssuanceSession::new(tenant_id, context, FlowType::AuthorizationCode);
        session.state = state;
        session
    }

    struct MockEventSubscriber;

    #[async_trait]
    impl IssuanceEventSubscriber for MockEventSubscriber {
        async fn subscribe(
            &self,
            _session_id: &str,
        ) -> Result<IssuanceEventStream, crate::domain::models::issuance::IssuanceError> {
            Ok(Box::pin(stream::empty()))
        }
    }

    #[tokio::test]
    async fn test_emit_terminal_event_completed() {
        let tenant_id = Uuid::new_v4();
        let mut session = create_test_session(tenant_id, IssuanceState::Completed);
        session.id = "test_session".to_string();
        let _sse = emit_terminal_event(&session);
    }

    #[tokio::test]
    async fn test_emit_terminal_event_failed() {
        let tenant_id = Uuid::new_v4();
        let mut session = create_test_session(tenant_id, IssuanceState::Failed);
        session.id = "test_session".to_string();
        let _sse = emit_terminal_event(&session);
    }
}