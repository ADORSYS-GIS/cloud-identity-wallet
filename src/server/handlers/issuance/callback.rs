use std::borrow::Cow;

use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cloud_wallet_openid4vc::issuance::client::{AuthorizationCallback, ClientError, Oid4vciClient};
use tracing::{debug, error, info, instrument, warn};

use crate::domain::models::issuance::{
    IssuanceError, IssuanceEvent, IssuanceTask, SseFailedEvent, transition_session,
};
use crate::server::{AppState, error::ApiError};
use crate::session::{IssuanceSession, IssuanceState, SessionStore};

/// OAuth 2.0 redirect URI invoked by the issuer authorization server.
#[instrument(skip_all)]
pub async fn authorization_callback<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    RawQuery(query): RawQuery,
) -> Result<Response, ApiError> {
    let query = query.unwrap_or_default();
    debug!(query = %query, "received authorization callback");

    let callback = Oid4vciClient::parse_authorization_callback(&query).map_err(|err| {
        warn!(error = %err, "invalid authorization callback query");
        invalid_callback("Invalid authorization callback.")
    })?;

    let session_id = callback
        .state()
        .filter(|state| !state.trim().is_empty())
        .ok_or_else(|| invalid_callback("Missing required state query parameter."))?
        .to_owned();
    tracing::Span::current().record("state", tracing::field::display(&session_id));

    let session = load_awaiting_authorization(&state.service.session, &session_id).await?;

    match callback {
        AuthorizationCallback::Success(response) => {
            let code_verifier = session
                .code_verifier
                .clone()
                .ok_or_else(|| invalid_callback("Session is missing its PKCE verifier."))?;

            transition_session(
                &state.service.session,
                session_id.as_str(),
                IssuanceState::Processing,
            )
            .await?;

            let task = IssuanceTask::new_authz_code(&session, response.code, code_verifier);
            state.service.issuance_engine.enqueue(&task).await?;

            info!(session_id = %session_id, "authorization callback accepted");
            Ok(StatusCode::OK.into_response())
        }
        AuthorizationCallback::Error(error_callback) => {
            let error = IssuanceError::from(ClientError::Authorization(error_callback.error));
            let error_code = error.error;
            let error_description = error.error_description;

            let failed = IssuanceEvent::Failed(SseFailedEvent::new(
                &session_id,
                error_code.to_string(),
                error_description,
                error.step,
            ));
            let event_publisher = &state.service.issuance_engine.event_publisher;
            let publish_result = event_publisher.publish(&failed).await;
            if let Err(err) = &publish_result {
                warn!(error = %err, session_id = %session_id, "failed to publish authorization failure event");
            }

            state.service.session.remove(session_id.as_str()).await?;
            publish_result?;

            error!(session_id = %session_id, error = %error_code, "authorization callback failed");
            Ok(StatusCode::OK.into_response())
        }
    }
}

async fn load_awaiting_authorization<S: SessionStore>(
    session_store: &S,
    session_id: &str,
) -> Result<IssuanceSession, ApiError> {
    let session: Option<IssuanceSession> = session_store.get(session_id).await?;
    let Some(session) = session else {
        return Err(invalid_callback("Invalid authorization callback state."));
    };

    if session.state != IssuanceState::AwaitingAuthorization {
        return Err(invalid_callback("Invalid authorization callback state."));
    }
    Ok(session)
}

fn invalid_callback(description: impl Into<String>) -> ApiError {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        error: Cow::Borrowed("invalid_request"),
        error_description: Some(description.into()),
    }
}
