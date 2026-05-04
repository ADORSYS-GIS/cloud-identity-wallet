use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use crate::domain::models::consent::{
    ConsentErrorResponse, ConsentRequest, ConsentResponse, NextAction,
};
use crate::domain::models::issuance::{IssuanceEvent, IssuanceStep, ProcessingStep, SseFailedEvent, SseProcessingEvent};
use crate::server::AppState;
use crate::session::{FlowType, IssuanceSession, IssuanceState, SessionStore, transition};

pub async fn submit_consent<S: SessionStore + Clone>(
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

        // Emit failed event via the event publisher
        let event = IssuanceEvent::Failed(SseFailedEvent::new(
            &session.id,
            "consent_rejected",
            Some("User rejected the credential offer".to_string()),
            IssuanceStep::Internal,
        ));
        if let Err(e) = state.service.issuance_engine.event_publisher.publish(&event).await {
            tracing::warn!(
                session_id = %session.id,
                error = %e,
                "Failed to publish consent rejected event"
            );
        }

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

async fn handle_authorization_code_consent<S: SessionStore + Clone>(
    state: AppState<S>,
    mut session: IssuanceSession,
    payload: ConsentRequest,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, Json<ConsentErrorResponse>)> {
    // Build authorization URL using the OID4VCI client from the issuance engine
    let result = state
        .service
        .issuance_engine
        .client
        .build_authorization_url(
            &session.context,
            session.id.clone(),
            &payload.selected_configuration_ids,
        )
        .await
        .map_err(|e| bad_gateway(format!("Failed to build authorization URL: {e}")))?;

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

async fn handle_pre_authorized_consent<S: SessionStore + Clone>(
    state: AppState<S>,
    mut session: IssuanceSession,
    _payload: ConsentRequest,
) -> Result<(StatusCode, Json<ConsentResponse>), (StatusCode, Json<ConsentErrorResponse>)> {
    let tx_code_required = session
        .context
        .flow
        .tx_code_required();

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

        // Emit processing event via the event publisher
        let event = IssuanceEvent::Processing(SseProcessingEvent::new(
            &session.id,
            ProcessingStep::ExchangingToken,
        ));
        if let Err(e) = state.service.issuance_engine.event_publisher.publish(&event).await {
            tracing::warn!(
                session_id = %session.id,
                error = %e,
                "Failed to publish processing event"
            );
        }

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

fn not_found(session_id: &str) -> (StatusCode, Json<ConsentErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ConsentErrorResponse {
            error: "session_not_found",
            error_description: format!("Session {} does not exist", session_id),
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
