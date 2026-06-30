use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{info, instrument, warn};

use crate::domain::models::credential::CredentialError;
use crate::domain::models::presentation::{
    ConsentStatus, CredentialSelection, PresentationConsentRequest, PresentationConsentResponse,
    PresentationEngine, PresentationError, PresentationErrorCode, VerifierDirectPostResponse,
};
use crate::server::AppState;
use crate::server::error::{ApiError, ApiJson, IntoApiError};
use crate::server::responses::ResponseBody;
use crate::session::{
    PresentationFlow, PresentationSession, PresentationState, SessionStore,
    transition_presentation_session,
};

use cloud_wallet_openid4vc::oid4vp::error::AuthorizationErrorCode;

#[instrument(skip_all)]
pub async fn submit_presentation_consent<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<uuid::Uuid>,
    Path(session_id): Path<String>,
    ApiJson(payload): ApiJson<PresentationConsentRequest>,
) -> Result<Response, ApiError> {
    info!(session_id = %session_id, accepted = payload.accepted, "received presentation consent request");

    let mut session: PresentationSession = state
        .service
        .session
        .get(session_id.as_str())
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| PresentationError::session_not_found(&session_id).into_api_error())?;

    if session.tenant_id != tenant_id {
        return Err(PresentationError::session_not_found(&session_id).into_api_error());
    }

    if session.state != PresentationState::AwaitingConsent {
        return Err(PresentationError::invalid_state(format!(
            "Session '{}' is not in awaiting_consent state (current: {:?})",
            session_id, session.state
        ))
        .into_api_error());
    }

    if !payload.accepted {
        if payload.selected_credentials.is_some() || payload.transaction_data_acknowledged.is_some()
        {
            return Err(PresentationError::new(
                PresentationErrorCode::InvalidRequest,
                "selected_credentials and transaction_data_acknowledged must not be present when accepted is false",
            )
            .into_api_error());
        }
        return handle_rejection(&state, &session_id, &mut session).await;
    }

    validate_selections(&session, &payload)?;

    if session.context.has_transaction_data() && payload.transaction_data_acknowledged != Some(true)
    {
        return Err(PresentationError::transaction_data_not_acknowledged().into_api_error());
    }

    let mut session: PresentationSession = state
        .service
        .session
        .consume(session_id.as_str())
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| PresentationError::session_not_found(&session_id).into_api_error())?;

    handle_acceptance(&state, &session_id, &mut session, &payload).await
}

fn validate_selections(
    session: &PresentationSession,
    payload: &PresentationConsentRequest,
) -> Result<(), ApiError> {
    let selections = payload.selected_credentials.as_ref().ok_or_else(|| {
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

    let provided_query_ids: std::collections::HashSet<String> =
        selections.iter().map(|s| s.query_id.clone()).collect();

    // Validate every provided query_id exists in the DCQL queries.
    let all_query_ids: std::collections::HashSet<String> = session
        .context
        .dcql_query
        .credentials
        .iter()
        .map(|q| q.id.clone())
        .collect();

    let unknown: Vec<&String> = provided_query_ids
        .iter()
        .filter(|id| !all_query_ids.contains(*id))
        .collect();
    if !unknown.is_empty() {
        return Err(PresentationError::invalid_credential_selection(format!(
            "provided query IDs {:?} are not part of the DCQL query",
            unknown
        ))
        .into_api_error());
    }

    // If credential_sets are present, validate against the set logic.
    // Every required set must have at least one satisfiable option covered;
    // optional sets may be skipped entirely.
    if let Some(credential_sets) = &session.context.dcql_query.credential_sets {
        let mut all_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for set in credential_sets {
            let is_required = set.required.unwrap_or(true);
            let satisfied_option = set.options.iter().find(|option| {
                option
                    .iter()
                    .all(|cq_id| provided_query_ids.contains(cq_id))
            });

            if !is_required {
                continue;
            }

            match satisfied_option {
                Some(option) => {
                    for id in option {
                        all_ids.insert(id.clone());
                    }
                }
                None => {
                    return Err(PresentationError::invalid_credential_selection(format!(
                        "required credential set is not satisfied; provided: {:?}, required: {:?}",
                        provided_query_ids, set.options
                    ))
                    .into_api_error());
                }
            }
        }

        // Also ensure that non-required (optional) sets that are satisfied
        // don't have extraneous query IDs that don't belong to any set option.
        let valid_ids: std::collections::HashSet<String> = all_ids;
        let mut extra_ids: Vec<&String> = Vec::new();

        for id in &provided_query_ids {
            if !valid_ids.contains(id) {
                extra_ids.push(id);
            }
        }

        // If we have extra IDs that don't belong to any required set option,
        // check if they belong to optional sets.
        if !extra_ids.is_empty() {
            let all_valid_ids: std::collections::HashSet<String> = credential_sets
                .iter()
                .flat_map(|s| &s.options)
                .flat_map(|o| o.iter().cloned())
                .collect();

            let truly_extra: Vec<&String> = extra_ids
                .into_iter()
                .filter(|id| !all_valid_ids.contains(*id))
                .collect();

            if !truly_extra.is_empty() {
                return Err(PresentationError::invalid_credential_selection(format!(
                    "extra query IDs {:?} not covered by any credential set option",
                    truly_extra
                ))
                .into_api_error());
            }
        }
    } else {
        // No credential_sets: every credential query must be covered.
        let required_query_ids: std::collections::HashSet<String> = session
            .dcql_result
            .selected_credential_query_ids
            .iter()
            .cloned()
            .collect();

        if provided_query_ids != required_query_ids {
            return Err(PresentationError::invalid_credential_selection(format!(
                "selected credentials must cover exactly the query IDs {:?}, got {:?}",
                required_query_ids, provided_query_ids
            ))
            .into_api_error());
        }
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

    Ok(())
}

async fn handle_rejection<S: SessionStore + Clone>(
    state: &AppState<S>,
    session_id: &str,
    session: &mut PresentationSession,
) -> Result<Response, ApiError> {
    info!(session_id = %session_id, "presentation consent rejected");

    let consumed: PresentationSession = state
        .service
        .session
        .consume(session_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| PresentationError::session_not_found(session_id).into_api_error())?;
    *session = consumed;

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
        .upsert(session_id, session)
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
    session_id: &str,
    session: &mut PresentationSession,
    payload: &PresentationConsentRequest,
) -> Result<Response, ApiError> {
    let selections = payload.selected_credentials.as_ref().unwrap();

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
            transition_to_failed(state, session_id, session).await;
            return Err(e.into_api_error());
        }
    };

    transition_presentation_session(session, PresentationState::Completed)
        .map_err(ApiError::from)?;

    state
        .service
        .session
        .upsert(session_id, session)
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
                other => PresentationError::presentation_build_failed(other).into_api_error(),
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
