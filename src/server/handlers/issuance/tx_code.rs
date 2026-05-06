use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use cloud_wallet_openid4vc::issuance::{client::IssuanceFlow, credential_offer::TxCode};
use tracing::{info, instrument};

use crate::domain::models::issuance::{
    IssuanceTask, TxCodeError, TxCodeRequest, TxCodeResponse, transition_session,
};
use crate::server::{AppState, error::ApiError, responses::ResponseBody};
use crate::session::{IssuanceSession, IssuanceState, SessionStore};

/// Submit the transaction code required by a pre-authorized code issuance flow.
#[instrument(skip_all, fields(session_id = %session_id))]
pub async fn submit_transaction_code<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Json(payload): Json<TxCodeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let session = load_awaiting_tx_code(&state.service.session, &session_id).await?;

    payload.validate_against(tx_code_spec(&session)?)?;
    let pre_authorized_code = pre_authorized_code(&session)?;

    transition_session(
        &state.service.session,
        session_id.as_str(),
        IssuanceState::Processing,
    )
    .await?;

    let tx_code = Some(payload.tx_code);
    let task = IssuanceTask::new_pre_authz_code(&session, pre_authorized_code, tx_code);
    state.service.issuance_engine.enqueue(&task).await?;

    info!(session_id = %session_id, "transaction code accepted");
    Ok(ResponseBody::new(
        StatusCode::ACCEPTED,
        TxCodeResponse { session_id },
    ))
}

async fn load_awaiting_tx_code<S: SessionStore>(
    session_store: &S,
    session_id: &str,
) -> Result<IssuanceSession, TxCodeError> {
    let session: Option<IssuanceSession> = session_store.get(session_id).await?;
    let Some(session) = session else {
        return Err(TxCodeError::session_not_found(session_id));
    };

    if session.state != IssuanceState::AwaitingTxCode {
        return Err(TxCodeError::not_awaiting_tx_code(session.state));
    }
    Ok(session)
}

fn tx_code_spec(session: &IssuanceSession) -> Result<&TxCode, TxCodeError> {
    session
        .context
        .flow
        .tx_code_spec()
        .ok_or_else(TxCodeError::tx_code_not_required)
}

fn pre_authorized_code(session: &IssuanceSession) -> Result<String, TxCodeError> {
    match &session.context.flow {
        IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code,
            ..
        } => Ok(pre_authorized_code.clone()),
        IssuanceFlow::AuthorizationCode { .. } => Err(TxCodeError::not_pre_authorized_flow()),
    }
}
