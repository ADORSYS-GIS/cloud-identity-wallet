use axum::{
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;

use crate::domain::session_store::Error as StoreError;
use crate::server::handlers::issuance::{ErrorResponse, IssuanceError};
use crate::server::sse::SseEvent;
use crate::server::AppState;
use crate::session::FailureStep;

pub async fn cancel_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, axum::Json<ErrorResponse>)> {
    let session = state
        .session_store
        .get(&session_id)
        .await
        .map_err(|e| match e {
            StoreError::Expired(_) => IssuanceError::SessionExpired,
            _ => IssuanceError::SessionNotFound,
        })?;

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
        .session_store
        .delete(&session_id)
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

    Ok(StatusCode::NO_CONTENT)
}
