//! HTTP handler for consent submission.

use crate::domain::models::consent::{ConsentError, ConsentRequest, ConsentResponse, NextAction};
use crate::domain::models::issuance::FlowType;
use crate::domain::models::issuance::{
    IssuanceEvent, IssuanceStep, ProcessingStep, SseFailedEvent, SseProcessingEvent,
};
use crate::server::{AppState, error::ApiError, responses::ResponseBody};
use crate::session::{IssuanceSession, IssuanceState, SessionStore, transition};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

/// Submit consent for a credential issuance session.
pub async fn submit_consent<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Path(session_id): Path<String>,
    Json(payload): Json<ConsentRequest>,
) -> Result<ResponseBody<ConsentResponse>, ApiError> {
    let mut session: IssuanceSession = state
        .service
        .session
        .get(session_id.as_str())
        .await
        .map_err(|e| ConsentError::Storage(e.into()))?
        .ok_or_else(|| ConsentError::NotFound(session_id.clone()))?;

    if session.state != IssuanceState::AwaitingConsent {
        return Err(ConsentError::InvalidState.into());
    }

    if !payload.accepted {
        transition(&mut session, IssuanceState::Failed)
            .map_err(|e| ConsentError::Storage(e.into()))?;
        state
            .service
            .session
            .upsert(session_id.as_str(), &session)
            .await
            .map_err(|e| ConsentError::Storage(e.into()))?;

        // Emit failed event via the event publisher
        let event = IssuanceEvent::Failed(SseFailedEvent::new(
            &session.id,
            "consent_rejected",
            Some("User rejected the credential offer".to_string()),
            IssuanceStep::Internal,
        ));
        if let Err(e) = state
            .service
            .issuance_engine
            .event_publisher
            .publish(&event)
            .await
        {
            tracing::warn!(
                session_id = %session.id,
                error = %e,
                "Failed to publish consent rejected event"
            );
        }

        return Ok(ResponseBody::new(
            StatusCode::OK,
            ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::Rejected,
                authorization_url: None,
            },
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
) -> Result<ResponseBody<ConsentResponse>, ApiError> {
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
        .map_err(|e| {
            ConsentError::AuthorizationUrlFailed(format!("Failed to build authorization URL: {e}"))
        })?;

    // Store the PKCE verifier in the session
    session.code_verifier = Some(result.pkce_verifier);

    transition(&mut session, IssuanceState::AwaitingAuthorization)
        .map_err(|e| ConsentError::Storage(e.into()))?;
    state
        .service
        .session
        .upsert(session.id.as_str(), &session)
        .await
        .map_err(|e| ConsentError::Storage(e.into()))?;

    Ok(ResponseBody::new(
        StatusCode::OK,
        ConsentResponse {
            session_id: session.id.clone(),
            next_action: NextAction::Redirect,
            authorization_url: Some(result.authz_url.to_string()),
        },
    ))
}

async fn handle_pre_authorized_consent<S: SessionStore + Clone>(
    state: AppState<S>,
    mut session: IssuanceSession,
    _payload: ConsentRequest,
) -> Result<ResponseBody<ConsentResponse>, ApiError> {
    let tx_code_required = session.context.flow.tx_code_required();

    if tx_code_required {
        transition(&mut session, IssuanceState::AwaitingTxCode)
            .map_err(|e| ConsentError::Storage(e.into()))?;
        state
            .service
            .session
            .upsert(session.id.as_str(), &session)
            .await
            .map_err(|e| ConsentError::Storage(e.into()))?;

        Ok(ResponseBody::new(
            StatusCode::OK,
            ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::ProvideTxCode,
                authorization_url: None,
            },
        ))
    } else {
        transition(&mut session, IssuanceState::Processing)
            .map_err(|e| ConsentError::Storage(e.into()))?;
        state
            .service
            .session
            .upsert(session.id.as_str(), &session)
            .await
            .map_err(|e| ConsentError::Storage(e.into()))?;

        // Emit processing event via the event publisher
        let event = IssuanceEvent::Processing(SseProcessingEvent::new(
            &session.id,
            ProcessingStep::ExchangingToken,
        ));
        if let Err(e) = state
            .service
            .issuance_engine
            .event_publisher
            .publish(&event)
            .await
        {
            tracing::warn!(
                session_id = %session.id,
                error = %e,
                "Failed to publish processing event"
            );
        }

        Ok(ResponseBody::new(
            StatusCode::OK,
            ConsentResponse {
                session_id: session.id.clone(),
                next_action: NextAction::None,
                authorization_url: None,
            },
        ))
    }
}
