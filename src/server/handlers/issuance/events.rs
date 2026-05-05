//! SSE handler for issuance session events.

use std::borrow::Cow;
use std::pin::Pin;
use std::time::Duration;

use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, KeepAliveStream, Sse},
    },
};
use futures::stream::{Stream, StreamExt};
use time::UtcDateTime;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::domain::models::issuance::{
    IssuanceEvent, IssuanceStep, SseCompletedEvent, SseFailedEvent,
};
use crate::domain::ports::IssuanceEventStream;
use crate::server::AppState;
use crate::server::error::ApiError;
use crate::session::{IssuanceSession, IssuanceState, SessionStore};

/// SSE response type with keepalive support.
type SseBody = Sse<KeepAliveStream<Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>>>>;

/// Keepalive interval in seconds (per spec: 15 seconds).
const KEEPALIVE_INTERVAL_SECS: u64 = 15;

/// Header to disable nginx buffering for SSE streams.
const X_ACCEL_BUFFERING: &str = "X-Accel-Buffering";

/// GET /api/v1/issuance/{session_id}/events

#[instrument(skip_all)]
pub async fn get_session_events<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Extension(tenant_id): Extension<Uuid>,
) -> Result<Response, ApiError> {
    debug!(session_id = %session_id, tenant_id = %tenant_id, "SSE connection request");

    let session = load_session(&state.service.session, &session_id, tenant_id).await?;

    if session.state.is_terminal() {
        debug!(session_id = %session_id, state = ?session.state, "Session in terminal state");
        return Ok((build_sse_headers(), emit_terminal_event(&session)).into_response());
    }

    let stream = state
        .service
        .event_subscriber
        .subscribe(&session_id)
        .await
        .map_err(|e| ApiError::internal(e))?;

    debug!(session_id = %session_id, "SSE stream established");
    Ok((build_sse_headers(), build_sse_stream(stream)).into_response())
}

/// Loads a session and validates tenant ownership.
async fn load_session<S: SessionStore>(
    session_store: &S,
    session_id: &str,
    tenant_id: Uuid,
) -> Result<IssuanceSession, ApiError> {
    let session: Option<IssuanceSession> = session_store
        .get(session_id)
        .await
        .map_err(|e| ApiError::internal(e))?;
    let Some(session) = session else {
        return Err(session_not_found());
    };

    if session.tenant_id != tenant_id {
        warn!(
            session_id = %session_id,
            tenant_id = %tenant_id,
            session_tenant_id = %session.tenant_id,
            "Tenant mismatch"
        );
        return Err(session_not_found());
    }

    Ok(session)
}

/// Returns a 404 error for session not found or tenant mismatch.
fn session_not_found() -> ApiError {
    ApiError {
        status: StatusCode::NOT_FOUND,
        error: Cow::Borrowed("session_not_found"),
        error_description: Some("Session not found or has expired.".into()),
    }
}

/// Builds the required SSE response headers.
/// Per spec: Content-Type, Cache-Control, Connection, X-Accel-Buffering.
fn build_sse_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
    headers.insert(X_ACCEL_BUFFERING, "no".parse().unwrap());
    headers
}

/// Creates a keepalive configuration per spec: `: keepalive\n\n` every 15 seconds.
fn keepalive_config() -> KeepAlive {
    KeepAlive::new()
        .interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS))
        .text("keepalive")
}

/// Emits a terminal event for a session that is already in a terminal state.
/// Used for re-hydration when a client reconnects to a completed/failed session.
fn emit_terminal_event(session: &IssuanceSession) -> SseBody {
    use futures::stream;

    let event = match session.state {
        IssuanceState::Completed => {
            IssuanceEvent::Completed(SseCompletedEvent::new(&session.id, vec![], vec![]))
        }
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
    Sse::new(boxed).keep_alive(keepalive_config())
}

/// Builds an SSE stream from an issuance event stream.
/// Applies keepalive comments every 15 seconds to prevent proxy timeouts.
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

    let boxed: Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>> =
        Box::pin(sse_stream);
    Sse::new(boxed).keep_alive(keepalive_config())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::issuance::FlowType;
    use cloud_wallet_openid4vc::issuance::client::ResolvedOfferContext;

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
