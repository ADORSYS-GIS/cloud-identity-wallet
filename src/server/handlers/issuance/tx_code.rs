use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::domain::models::issuance::IssuanceTask;
use crate::server::AppState;
use crate::server::handlers::issuance::{
    ErrorResponse, IssuanceError, TxCodeRequest, TxCodeResponse,
};
use crate::server::sse::SseEvent;
use crate::session::{IssuanceSession, IssuanceState, ProcessingStep, SessionStore, TxCodeValidationError, validate_tx_code};

pub async fn submit_tx_code<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Json(payload): Json<TxCodeRequest>,
) -> Result<(StatusCode, Json<TxCodeResponse>), (StatusCode, Json<ErrorResponse>)> {
    let session: IssuanceSession = state
        .issuance_store
        .get(session_id.as_str())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get session");
            IssuanceError::SessionNotFound
        })?
        .ok_or(IssuanceError::SessionNotFound)?;

    if session.state != IssuanceState::AwaitingTxCode {
        return Err(IssuanceError::InvalidSessionState(format!(
            "Session is not awaiting a transaction code (current state: {:?})",
            session.state
        ))
        .into());
    }

    let tx_code_spec = session
        .context
        .offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.as_ref())
        .and_then(|g| g.tx_code.as_ref());

    if let Some(spec) = tx_code_spec
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

    // Update session state to processing
    let tx_code = payload.tx_code.clone();
    let mut updated_session = session.clone();
    updated_session.state = IssuanceState::Processing;
    updated_session.submitted_tx_code = Some(payload.tx_code);
    state
        .issuance_store
        .upsert(session_id.as_str(), &updated_session)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to update session");
            IssuanceError::SessionNotFound
        })?;

    // Emit processing SSE event
    let event = SseEvent::processing(session_id.clone(), ProcessingStep::ExchangingToken);
    state.broadcaster.send(&session_id, event);

    // Enqueue issuance task
    let pre_authorized_code = session
        .context
        .offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.as_ref())
        .map(|g| g.pre_authorized_code.clone())
        .unwrap_or_default();
    let task = IssuanceTask::new_pre_authz_code(&updated_session, pre_authorized_code, Some(tx_code));
    state
        .issuance_engine
        .enqueue(&task)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to enqueue issuance task");
            IssuanceError::SessionNotFound
        })?;

    Ok((StatusCode::ACCEPTED, Json(TxCodeResponse { session_id })))
}
