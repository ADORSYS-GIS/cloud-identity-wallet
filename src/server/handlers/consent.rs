use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use cloud_wallet_openid4vc::issuance::client::{IssuanceFlow, ResolvedOfferContext};

use crate::domain::models::consent::{
    ConsentErrorResponse, ConsentRequest, ConsentResponse, NextAction,
};
use crate::server::AppState;
use crate::server::sse::{ErrorStep, ProcessingStep, SseEvent};
use crate::session::{FlowType, IssuanceSession, IssuanceState, SessionStore, transition};

pub async fn submit_consent<S: SessionStore>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Json(payload): Json<ConsentRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ConsentErrorResponse>)> {
    let mut session: IssuanceSession = state
        .service
        .session
        .get(session_id.as_str())
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
            .session
            .upsert(session_id.as_str(), &session)
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

async fn handle_authorization_code_consent<S: SessionStore>(
    state: AppState<S>,
    mut session: IssuanceSession,
    payload: ConsentRequest,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, Json<ConsentErrorResponse>)> {
    // Build the IssuanceFlow from session data
    let flow = IssuanceFlow::AuthorizationCode {
        issuer_state: session.issuer_state.clone(),
    };

    // Build the resolved offer context
    let context = ResolvedOfferContext {
        offer: session.offer.clone(),
        issuer_metadata: session.issuer_metadata.clone(),
        as_metadata: session.authz_server_metadata.clone(),
        flow,
    };

    // Build authorization URL using the OID4VCI client
    let result = state
        .service
        .oid4vci_client
        .build_authorization_url(
            &context,
            session.id.clone(),
            &payload.selected_configuration_ids,
        )
        .await
        .map_err(|e| bad_gateway(&format!("Failed to build authorization URL: {e}")))?;

    // Store the PKCE verifier in the session
    session.code_verifier = Some(result.pkce_verifier);

    transition(&mut session, IssuanceState::AwaitingAuthorization).map_err(internal_error)?;
    state
        .service
        .session
        .upsert(session.id.as_str(), &session)
        .await
        .map_err(internal_error)?;

    Ok((
        StatusCode::OK,
        Json(ConsentResponse {
            session_id: session.id.clone(),
            next_action: NextAction::Redirect,
            authorization_url: Some(result.authz_url.to_string()),
        }),
    ))
}

async fn handle_pre_authorized_consent<S: SessionStore>(
    state: AppState<S>,
    mut session: IssuanceSession,
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
            .session
            .upsert(session.id.as_str(), &session)
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
            .session
            .upsert(session.id.as_str(), &session)
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
            error: "internal_error",
            error_description: e.to_string(),
        }),
    )
}

fn bad_gateway(e: impl std::fmt::Display) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(ConsentErrorResponse {
            error: "bad_gateway",
            error_description: e.to_string(),
        }),
    )
}
