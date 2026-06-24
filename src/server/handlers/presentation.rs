use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use tracing::{info, instrument, warn};

use crate::domain::models::credential::CredentialError;
use crate::domain::models::presentation::{
    ConsentStatus, CredentialSelection, PresentationConsentRequest,
    PresentationConsentResponse, PresentationError, PresentationErrorCode,
    PresentationEngine, VerifierDirectPostResponse,
};
use crate::server::error::{ApiError, IntoApiError};
use crate::server::responses::ResponseBody;
use crate::session::{
    transition_presentation_session, PresentationFlow, PresentationSession, PresentationState,
    SessionStore,
};
use crate::server::AppState;

use cloud_wallet_openid4vc::oid4vp::error::AuthorizationErrorCode;

#[instrument(skip_all)]
pub async fn submit_presentation_consent<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<uuid::Uuid>,
    Path(session_id): Path<String>,
    Json(payload): Json<PresentationConsentRequest>,
) -> Result<Response, ApiError> {
    info!(session_id = %session_id, accepted = payload.accepted, "received presentation consent request");

    let mut session: PresentationSession = state
        .service
        .session
        .get(session_id.as_str())
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| PresentationError::session_not_found(&session_id).into_api_error())?;

    if session.state != PresentationState::AwaitingConsent {
        return Err(PresentationError::invalid_state(format!(
            "Session '{}' is not in awaiting_consent state (current: {:?})",
            session_id, session.state
        ))
        .into_api_error());
    }

    if session.tenant_id != tenant_id {
        return Err(PresentationError::session_not_found(&session_id).into_api_error());
    }

    if !payload.accepted {
        return handle_rejection(&state, session_id, &mut session).await;
    }

    handle_acceptance(&state, session_id, &mut session, &payload).await
}

async fn handle_rejection<S: SessionStore + Clone>(
    state: &AppState<S>,
    session_id: String,
    session: &mut PresentationSession,
) -> Result<Response, ApiError> {
    info!(session_id = %session_id, "presentation consent rejected");

    match state
        .service
        .presentation_engine
        .reject_presentation(&session.context, AuthorizationErrorCode::AccessDenied)
        .await
    {
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, session_id = %session_id, "best-effort rejection to verifier failed");
        }
    }

    transition_presentation_session(session, PresentationState::Completed)
        .map_err(ApiError::from)?;

    state
        .service
        .session
        .upsert(session_id.as_str(), session)
        .await
        .map_err(ApiError::internal)?;

    let resp = PresentationConsentResponse {
        status: ConsentStatus::Rejected,
        redirect_uri: None,
        verifier_response: None,
    };
    Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
}

async fn handle_acceptance<S: SessionStore + Clone>(
    state: &AppState<S>,
    session_id: String,
    session: &mut PresentationSession,
    payload: &PresentationConsentRequest,
) -> Result<Response, ApiError> {
    let selections = payload
        .selected_credentials
        .as_ref()
        .ok_or_else(|| {
            PresentationError::new(
                PresentationErrorCode::InvalidRequest,
                "selected_credentials is required when accepted is true",
            )
        })?;

    if selections.is_empty() {
        return Err(PresentationError::new(
            PresentationErrorCode::InvalidRequest,
            "selected_credentials must not be empty",
        )
        .into_api_error());
    }

    let required_query_ids: std::collections::HashSet<String> = session
        .dcql_result
        .selected_credential_query_ids
        .iter()
        .cloned()
        .collect();
    let provided_query_ids: std::collections::HashSet<String> =
        selections.iter().map(|s| s.query_id.clone()).collect();

    if provided_query_ids != required_query_ids {
        return Err(PresentationError::invalid_credential_selection(format!(
            "selected credentials must cover exactly the query IDs {:?}, got {:?}",
            required_query_ids, provided_query_ids
        ))
        .into_api_error());
    }

    for selection in selections {
        let candidates = session
            .dcql_result
            .candidates
            .get(&selection.query_id)
            .ok_or_else(|| {
                PresentationError::invalid_credential_selection(format!(
                    "no candidates found for query_id '{}'",
                    selection.query_id
                ))
            })?;

        let cred_id_lower = selection.credential_id.to_lowercase();
        let valid = candidates
            .iter()
            .any(|c| c.credential_id.to_lowercase() == cred_id_lower);
        if !valid {
            return Err(PresentationError::invalid_credential_selection(format!(
                "credential '{}' is not a valid candidate for query_id '{}'",
                selection.credential_id, selection.query_id
            ))
            .into_api_error());
        }
    }

    if session.context.has_transaction_data()
        && payload.transaction_data_acknowledged != Some(true)
    {
        return Err(PresentationError::transaction_data_not_acknowledged().into_api_error());
    }

    let selected_credentials = build_selected_credentials(
        &state.service.presentation_engine,
        &session.context,
        selections,
        session.tenant_id,
        &session.dcql_result,
        &session.context.transaction_data,
    )
    .await?;

    let direct_post_response = match state
        .service
        .presentation_engine
        .submit_presentation(&session.context, selected_credentials)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            transition_to_failed(state, &session_id, session).await;
            return Err(e.into_api_error());
        }
    };

    transition_presentation_session(session, PresentationState::Completed)
        .map_err(ApiError::from)?;

    state
        .service
        .session
        .upsert(session_id.as_str(), session)
        .await
        .map_err(ApiError::internal)?;

    let resp = build_consent_response(&session.flow, direct_post_response.into());
    Ok(ResponseBody::new(StatusCode::OK, resp).into_response())
}

async fn build_selected_credentials(
    engine: &PresentationEngine,
    ctx: &cloud_wallet_openid4vc::oid4vp::client::PresentationContext,
    selections: &[CredentialSelection],
    tenant_id: uuid::Uuid,
    dcql_result: &cloud_wallet_openid4vc::oid4vp::selection::SelectionResult,
    transaction_data: &[cloud_wallet_openid4vc::oid4vp::transaction_data::TransactionData<'_>],
) -> Result<Vec<cloud_wallet_openid4vc::oid4vp::presentation::SelectedCredential>, ApiError> {
    let mut selected = Vec::with_capacity(selections.len());

    for selection in selections {
        let cred_id = uuid::Uuid::parse_str(&selection.credential_id).map_err(|_| {
            PresentationError::invalid_credential_selection(format!(
                "'{}' is not a valid UUID",
                selection.credential_id
            ))
            .into_api_error()
        })?;

        let credential = engine
            .credential_repo
            .find_by_id(cred_id, tenant_id)
            .await
            .map_err(|e| match e {
                CredentialError::NotFound { .. } => {
                    PresentationError::invalid_credential_selection(format!(
                        "credential '{}' not found",
                        selection.credential_id
                    ))
                    .into_api_error()
                }
                other => ApiError::internal(other),
            })?;

        let sc = engine
            .build_selected_credential_from_raw(
                ctx,
                &selection.query_id,
                tenant_id,
                &credential,
                dcql_result,
                transaction_data,
            )
            .await
            .map_err(IntoApiError::into_api_error)?;

        selected.push(sc);
    }

    Ok(selected)
}

fn build_consent_response(
    flow: &PresentationFlow,
    verifier_response: VerifierDirectPostResponse,
) -> PresentationConsentResponse {
    match flow {
        PresentationFlow::CrossDevice => PresentationConsentResponse {
            status: ConsentStatus::Completed,
            redirect_uri: None,
            verifier_response: Some(verifier_response),
        },
        PresentationFlow::SameDevice => PresentationConsentResponse {
            status: ConsentStatus::Completed,
            redirect_uri: verifier_response.redirect_uri.clone(),
            verifier_response: None,
        },
    }
}

async fn transition_to_failed<S: SessionStore + Clone>(
    state: &AppState<S>,
    session_id: &str,
    session: &mut PresentationSession,
) {
    if let Err(e) = transition_presentation_session(session, PresentationState::Failed) {
        warn!(error = %e, session_id = %session_id, "failed to transition session to Failed state");
    } else if let Err(e) = state.service.session.upsert(session_id, session).await {
        warn!(error = %e, session_id = %session_id, "failed to persist session in Failed state");
    }
}