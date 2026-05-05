//! HTTP handler for consent submission.

use std::borrow::Cow;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, info, instrument, warn};

use crate::domain::models::issuance::{
    FlowType, IssuanceEvent, IssuanceStep, IssuanceTask, SseFailedEvent, transition_session,
};
use crate::server::{AppState, error::ApiError};
use crate::session::{IssuanceSession, IssuanceState, SessionStore};
use crate::{
    domain::models::consent::{ConsentRequest, ConsentResponse, NextAction},
    server::responses::ResponseBody,
};

/// Submit consent for a credential issuance session.
#[instrument(skip_all)]
pub async fn submit_consent<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Json(payload): Json<ConsentRequest>,
) -> Result<Response, ApiError> {
    debug!(session_id = %session_id, "received consent request");

    let mut session = load_awaiting_consent(&state.service.session, &session_id).await?;

    if !payload.accepted {
        return handle_rejected_consent(&state, session_id).await;
    }

    match session.flow {
        FlowType::AuthorizationCode => {
            handle_authorization_code_consent(state, session_id, &mut session, payload).await
        }
        FlowType::PreAuthorizedCode => {
            handle_pre_authorized_consent(state, session_id, session).await
        }
    }
}

async fn handle_rejected_consent<S: SessionStore + Clone>(
    state: &AppState<S>,
    session_id: String,
) -> Result<Response, ApiError> {
    let event = IssuanceEvent::Failed(SseFailedEvent::new(
        &session_id,
        "consent_rejected".to_string(),
        Some("User rejected the credential offer".to_string()),
        IssuanceStep::Internal,
    ));
    let event_publisher = &state.service.issuance_engine.event_publisher;
    let publish_result = event_publisher.publish(&event).await;
    if let Err(err) = &publish_result {
        warn!(error = %err, session_id = %session_id, "failed to publish consent rejected event");
    }

    state.service.session.remove(session_id.as_str()).await?;
    publish_result?;

    warn!(session_id = %session_id, "consent rejected by user");

    let resp = ConsentResponse {
        session_id: session_id.clone(),
        next_action: NextAction::Rejected,
        authorization_url: None,
    };
    Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
}

async fn handle_authorization_code_consent<S: SessionStore + Clone>(
    state: AppState<S>,
    session_id: String,
    session: &mut IssuanceSession,
    payload: ConsentRequest,
) -> Result<Response, ApiError> {
    // Build authorization URL using the OID4VCI client from the issuance engine
    let result = state
        .service
        .issuance_engine
        .client
        .build_authorization_url(
            &session.context,
            session_id.clone(),
            &payload.selected_configuration_ids,
        )
        .await
        .map_err(ApiError::internal)?;

    // Store the PKCE verifier in the session
    session.code_verifier = Some(result.pkce_verifier);
    session.state = IssuanceState::AwaitingAuthorization;

    // Update session with code_verifier
    state
        .service
        .session
        .upsert(session_id.as_str(), &session)
        .await?;

    let resp = ConsentResponse {
        session_id: session_id.clone(),
        next_action: NextAction::Redirect,
        authorization_url: Some(result.authz_url.to_string()),
    };
    info!(session_id = %session_id, "consent accepted, redirecting to authorization URL");
    Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
}

async fn handle_pre_authorized_consent<S: SessionStore + Clone>(
    state: AppState<S>,
    session_id: String,
    session: IssuanceSession,
) -> Result<Response, ApiError> {
    let tx_code_required = session.context.flow.tx_code_required();

    if tx_code_required {
        transition_session(
            &state.service.session,
            &session_id,
            IssuanceState::AwaitingTxCode,
        )
        .await?;

        let resp = ConsentResponse {
            session_id: session_id.clone(),
            next_action: NextAction::ProvideTxCode,
            authorization_url: None,
        };
        info!(session_id = %session_id, "consent accepted, awaiting transaction code");
        Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
    } else {
        transition_session(
            &state.service.session,
            &session_id,
            IssuanceState::Processing,
        )
        .await?;

        let task = IssuanceTask::new_pre_auth_no_tx_code(&session);
        state.service.issuance_engine.enqueue(&task).await?;

        let resp = ConsentResponse {
            session_id: session_id.clone(),
            next_action: NextAction::None,
            authorization_url: None,
        };
        info!(session_id = %session_id, "consent accepted, processing issuance");
        Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
    }
}

async fn load_awaiting_consent<S: SessionStore>(
    session_store: &S,
    session_id: &str,
) -> Result<IssuanceSession, ApiError> {
    let session: Option<IssuanceSession> = session_store.get(session_id).await?;
    let Some(session) = session else {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            error: Cow::Borrowed("session_not_found"),
            error_description: Some("session_id does not exist or has expired.".into()),
        });
    };

    if session.state != IssuanceState::AwaitingConsent {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            error: Cow::Borrowed("invalid_session_state"),
            error_description: Some("Session is not in awaiting_consent state".into()),
        });
    }
    Ok(session)
}
