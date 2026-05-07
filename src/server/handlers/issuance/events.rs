//! SSE handler for issuance session events.

use std::{borrow::Cow, pin::Pin};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, KeepAliveStream, Sse},
    response::{IntoResponse, Response},
};
use futures::stream::Stream;
use futures::stream::StreamExt;
use time::UtcDateTime;
use tracing::{debug, instrument};

use crate::domain::ports::IssuanceEventStream;
use crate::server::AppState;
use crate::server::error::ApiError;
use crate::session::SessionStore;

/// GET /api/v1/issuance/{session_id}/events
#[instrument(skip_all)]
pub async fn get_session_events<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
) -> Result<Response, ApiError> {
    debug!(session_id = %session_id, "SSE connection request");

    // Check if session exists
    let exists = state.service.session.exists(session_id.as_str()).await?;

    if !exists {
        return Err(session_not_found());
    }

    let stream = state
        .service
        .issuance_engine
        .subscribe(&session_id)
        .await
        .map_err(ApiError::internal)?;

    debug!(session_id = %session_id, "SSE stream established");
    Ok((event_stream_to_sse(stream)).into_response())
}

/// SSE stream type for Axum responses.
type SseStream =
    Sse<KeepAliveStream<Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>>>>;

/// Converts an [`IssuanceEventStream`] into an [`Sse`] response.
fn event_stream_to_sse(stream: IssuanceEventStream) -> SseStream {
    let sse_stream = stream.map(move |event| {
        event
            .to_sse_event()
            .map(|e| e.id(UtcDateTime::now().unix_timestamp_nanos().to_string()))
    });
    let boxed_stream: Pin<Box<dyn Stream<Item = Result<Event, axum::Error>> + Send>> =
        Box::pin(sse_stream);
    Sse::new(boxed_stream).keep_alive(KeepAlive::default())
}

/// Returns a 404 error for session not found.
pub fn session_not_found() -> ApiError {
    ApiError {
        status: StatusCode::NOT_FOUND,
        error: Cow::Borrowed("session_not_found"),
        error_description: Some("Session not found or has expired.".into()),
    }
}
