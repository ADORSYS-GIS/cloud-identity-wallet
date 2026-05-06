use axum::{
    extract::{Path, State},
    http::StatusCode,
};

use crate::server::AppState;
use crate::server::handlers::issuance::{ErrorResponse, IssuanceError};
use crate::server::sse::SseEvent;
use crate::session::{FailureStep, IssuanceSession, SessionStore};

pub async fn cancel_session<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, axum::Json<ErrorResponse>)> {
    let session: IssuanceSession = state
        .issuance_store
        .get(session_id.as_str())
        .await
        .map_err(|e| match e {
            crate::session::SessionError::InvalidStateTransition(_, _) => {
                IssuanceError::SessionExpired
            }
            _ => IssuanceError::SessionNotFound,
        })?
        .ok_or(IssuanceError::SessionNotFound)?;

    if session.state.is_terminal() {
        return Err(IssuanceError::TerminalState.into());
    }

    let event = SseEvent::failed(
        session_id.clone(),
        "cancelled".to_string(),
        Some("Session cancelled by the user.".to_string()),
        FailureStep::Internal,
    );
    state.broadcaster.send(&session_id, event);

    state
        .issuance_store
        .remove(session_id.as_str())
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

    Ok(StatusCode::NO_CONTENT)
}
