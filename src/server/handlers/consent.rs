use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use cloud_wallet_openid4vc::issuance::authz_details::AuthorizationDetails;
use cloud_wallet_openid4vc::issuance::utils::pkce::{
    derive_pkce_challenge, generate_pkce_verifier,
};

use crate::domain::models::consent::{
    ConsentErrorResponse, ConsentRequest, ConsentResponse, NextAction,
};
use crate::server::AppState;
use crate::server::sse::{ErrorStep, ProcessingStep, SseEvent};
use crate::session::{FlowType, IssuanceState, transition};

pub async fn submit_consent(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(payload): Json<ConsentRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ConsentErrorResponse>)> {
    let mut session = state
        .service
        .session_repo
        .get(&session_id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found(&session_id))?;

    if session.is_expired() {
        return Err(expired(&session_id));
    }

    if session.state != IssuanceState::AwaitingConsent {
        return Err(invalid_state());
    }

    if !payload.accepted {
        transition(&mut session, IssuanceState::Failed).map_err(internal_error)?;
        state
            .service
            .session_repo
            .save(&session)
            .await
            .map_err(internal_error)?;

        emit_sse_event(
            &state.service.sse_broadcast,
            &session.id,
            SseEvent::failed(
                &session.id,
                "consent_rejected",
                Some("User rejected the credential offer"),
                ErrorStep::Internal,
            ),
        );

        return Ok((
            StatusCode::OK,
            Json(ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::Rejected,
                authorization_url: None,
            }),
        ));
    }

    match session.flow {
        FlowType::AuthorizationCode => {
            handle_authorization_code_consent(state, session, payload).await
        }
        FlowType::PreAuthorizedCode => handle_pre_authorized_consent(state, session, payload).await,
    }
}

async fn handle_authorization_code_consent(
    state: AppState,
    mut session: crate::session::IssuanceSession,
    payload: ConsentRequest,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, Json<ConsentErrorResponse>)> {
    let code_verifier = generate_pkce_verifier();
    let code_challenge = derive_pkce_challenge(&code_verifier);

    session.code_verifier = Some(code_verifier);

    let selected_ids: Vec<&str> = payload
        .selected_configuration_ids
        .iter()
        .map(|s| s.as_str())
        .collect();

    let authz_details = build_authorization_details(&session.offer, &selected_ids);

    let issuer_state = session.issuer_state.as_deref();

    let authz_url = state
        .service
        .authz_url_builder
        .build(
            &session.id,
            &code_challenge,
            issuer_state,
            authz_details.as_deref(),
            None,
            &session.authz_server_metadata,
        )
        .await
        .map_err(bad_gateway)?;

    transition(&mut session, IssuanceState::AwaitingAuthorization).map_err(internal_error)?;
    state
        .service
        .session_repo
        .save(&session)
        .await
        .map_err(internal_error)?;

    Ok((
        StatusCode::OK,
        Json(ConsentResponse {
            session_id: session.id.clone(),
            next_action: NextAction::Redirect,
            authorization_url: Some(authz_url),
        }),
    ))
}

async fn handle_pre_authorized_consent(
    state: AppState,
    mut session: crate::session::IssuanceSession,
    _payload: ConsentRequest,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, Json<ConsentErrorResponse>)> {
    let tx_code_required = session
        .offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.as_ref())
        .map(|pac| pac.tx_code.is_some())
        .unwrap_or(false);

    if tx_code_required {
        transition(&mut session, IssuanceState::AwaitingTxCode).map_err(internal_error)?;
        state
            .service
            .session_repo
            .save(&session)
            .await
            .map_err(internal_error)?;

        Ok((
            StatusCode::OK,
            Json(ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::ProvideTxCode,
                authorization_url: None,
            }),
        ))
    } else {
        transition(&mut session, IssuanceState::Processing).map_err(internal_error)?;
        state
            .service
            .session_repo
            .save(&session)
            .await
            .map_err(internal_error)?;

        emit_sse_event(
            &state.service.sse_broadcast,
            &session.id,
            SseEvent::processing(&session.id, ProcessingStep::ExchangingToken),
        );

        Ok((
            StatusCode::OK,
            Json(ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::None,
                authorization_url: None,
            }),
        ))
    }
}

fn build_authorization_details(
    offer: &cloud_wallet_openid4vc::issuance::credential_offer::CredentialOffer,
    selected_ids: &[&str],
) -> Option<Vec<AuthorizationDetails>> {
    let config_ids: Vec<&str> = if selected_ids.is_empty() {
        offer
            .credential_configuration_ids
            .iter()
            .map(|s| s.as_str())
            .collect()
    } else {
        selected_ids.to_vec()
    };

    if config_ids.is_empty() {
        return None;
    }

    let details: Vec<AuthorizationDetails> = config_ids
        .into_iter()
        .map(AuthorizationDetails::for_configuration)
        .collect();

    Some(details)
}

fn emit_sse_event(
    broadcast: &tokio::sync::broadcast::Sender<SseEvent>,
    session_id: &str,
    event: SseEvent,
) {
    if broadcast.send(event.clone()).is_err() {
        tracing::warn!(
            session_id = %session_id,
            "No active SSE listeners for session"
        );
    }
}

fn not_found(session_id: &str) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ConsentErrorResponse {
            error: "session_not_found",
            error_description: format!("Session {} does not exist or has expired", session_id),
        }),
    )
}

fn expired(session_id: &str) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ConsentErrorResponse {
            error: "session_not_found",
            error_description: format!("Session {} has expired", session_id),
        }),
    )
}

fn invalid_state() -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::CONFLICT,
        Json(ConsentErrorResponse {
            error: "invalid_session_state",
            error_description: "Session is not in awaiting_consent state".to_string(),
        }),
    )
}

fn internal_error(e: impl std::fmt::Display) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ConsentErrorResponse {
            error: "server_error",
            error_description: e.to_string(),
        }),
    )
}

fn bad_gateway(e: impl std::fmt::Display) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(ConsentErrorResponse {
            error: "authorization_url_build_failed",
            error_description: e.to_string(),
        }),
    )
}
