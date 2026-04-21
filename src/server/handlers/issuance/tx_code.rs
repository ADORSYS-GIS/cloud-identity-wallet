use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use std::sync::Arc;

use crate::domain::models::{ProcessingStep, SessionState, TxCodeValidationError, validate_tx_code};
use crate::domain::session_store::Error as StoreError;
use crate::server::handlers::issuance::{
    ErrorResponse, IssuanceError, TxCodeRequest, TxCodeResponse,
};
use crate::server::sse::SseEvent;
use crate::server::AppState;

pub async fn submit_tx_code(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<TxCodeRequest>,
) -> Result<(StatusCode, Json<TxCodeResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session = state
        .session_store
        .get(&session_id)
        .await
        .map_err(|e| match e {
            StoreError::Expired(_) => IssuanceError::SessionExpired,
            _ => IssuanceError::SessionNotFound,
        })?;

    if session.state != SessionState::AwaitingTxCode {
        return Err(IssuanceError::InvalidSessionState(format!(
            "Session is not awaiting a transaction code (current state: {:?})",
            session.state
        ))
        .into());
    }

    if let Some(ref spec) = session.tx_code
        && let Err(e) = validate_tx_code(spec, &payload.tx_code)
    {
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

    state
        .session_store
        .set_tx_code(&session_id, payload.tx_code)
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
