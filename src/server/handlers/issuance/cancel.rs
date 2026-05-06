use std::borrow::Cow;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{info, instrument, warn};

use crate::domain::models::issuance::{IssuanceEvent, IssuanceStep, SseFailedEvent};
use crate::server::{AppState, error::ApiError};
use crate::session::{IssuanceSession, SessionStore};

#[instrument(skip_all)]
pub async fn cancel_issuance<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
) -> Result<Response, ApiError> {
    let session: Option<IssuanceSession> = state.service.session.get(session_id.as_str()).await?;

    let Some(session) = session else {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            error: Cow::Borrowed("session_not_found"),
            error_description: Some("session_id does not exist or has expired.".into()),
        });
    };

    if session.state.is_terminal() {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            error: Cow::Borrowed("session_already_completed"),
            error_description: Some("Session is already completed or failed.".into()),
        });
    }

    let event = IssuanceEvent::Failed(SseFailedEvent::new(
        &session_id,
        "cancelled",
        Some("Session cancelled by the user.".to_string()),
        IssuanceStep::Internal,
    ));

    let event_publisher = &state.service.issuance_engine.event_publisher;
    let publish_result = event_publisher.publish(&event).await;
    if let Err(err) = &publish_result {
        warn!(error = %err, session_id = %session_id, "failed to publish cancel event");
    }

    state.service.session.remove(session_id.as_str()).await?;
    publish_result?;

    info!(session_id = %session_id, "session cancelled by user");

    Ok(StatusCode::NO_CONTENT.into_response())
}
