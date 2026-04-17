use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::domain::SessionStore;
use crate::domain::models::{FailureStep, ProcessingStep, SessionState, TxCodeValidationError};
use crate::server::sse::{SseBroadcaster, SseEvent};

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum IssuanceError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Invalid transaction code: {0}")]
    InvalidTxCode(String),
    #[error("Invalid session state: {0}")]
    InvalidSessionState(String),
    #[error("Session already in terminal state")]
    TerminalState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

impl From<&IssuanceError> for ErrorResponse {
    fn from(err: &IssuanceError) -> Self {
        match err {
            IssuanceError::SessionNotFound => Self {
                error: "session_not_found".to_string(),
                error_description: "No active session found for the given session_id.".to_string(),
            },
            IssuanceError::InvalidTxCode(desc) => Self {
                error: "invalid_tx_code".to_string(),
                error_description: desc.clone(),
            },
            IssuanceError::InvalidSessionState(desc) => Self {
                error: "invalid_session_state".to_string(),
                error_description: desc.clone(),
            },
            IssuanceError::TerminalState => Self {
                error: "invalid_session_state".to_string(),
                error_description:
                    "Session is already in a terminal state and cannot be cancelled.".to_string(),
            },
        }
    }
}

impl From<IssuanceError> for (StatusCode, Json<ErrorResponse>) {
    fn from(err: IssuanceError) -> Self {
        let response = ErrorResponse::from(&err);
        let status = match &err {
            IssuanceError::SessionNotFound => StatusCode::NOT_FOUND,
            IssuanceError::InvalidTxCode(_) => StatusCode::BAD_REQUEST,
            IssuanceError::InvalidSessionState(_) => StatusCode::CONFLICT,
            IssuanceError::TerminalState => StatusCode::CONFLICT,
        };
        (status, Json(response))
    }
}

#[derive(Debug, Deserialize)]
pub struct TxCodeRequest {
    pub tx_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxCodeResponse {
    pub session_id: String,
}

#[derive(Debug)]
pub struct IssuanceState {
    pub session_store: Arc<dyn SessionStore>,
    pub broadcaster: SseBroadcaster,
}

pub async fn submit_tx_code(
    State(state): State<Arc<IssuanceState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<TxCodeRequest>,
) -> Result<(StatusCode, Json<TxCodeResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session = state
        .session_store
        .get(&session_id)
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

    if session.state != SessionState::AwaitingTxCode {
        return Err(IssuanceError::InvalidSessionState(format!(
            "Session is not awaiting a transaction code (current state: {:?})",
            session.state
        ))
        .into());
    }

    if let Some(ref spec) = session.tx_code_spec {
        if let Err(e) = spec.validate_tx_code(&payload.tx_code) {
            let desc = match e {
                TxCodeValidationError::InvalidLength { expected, actual } => {
                    format!(
                        "Transaction code must be exactly {} characters (got {}).",
                        expected, actual
                    )
                }
                TxCodeValidationError::InvalidCharacters { expected } => {
                    format!(
                        "Transaction code must contain only {} characters.",
                        expected
                    )
                }
            };
            return Err(IssuanceError::InvalidTxCode(desc).into());
        }
    }

    state
        .session_store
        .set_tx_code(&session_id, payload.tx_code.clone())
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

    state
        .session_store
        .update_state(&session_id, SessionState::Processing)
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

    let event = SseEvent::processing(session_id.clone(), ProcessingStep::ExchangingToken);
    state.broadcaster.send(&session_id, event);

    Ok((StatusCode::ACCEPTED, Json(TxCodeResponse { session_id })))
}

pub async fn cancel_session(
    State(state): State<Arc<IssuanceState>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let session = state
        .session_store
        .get(&session_id)
        .await
        .map_err(|_| IssuanceError::SessionNotFound)?;

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
