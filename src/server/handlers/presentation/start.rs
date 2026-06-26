use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::{PresentationSession, SessionStore};

#[derive(Debug, Deserialize)]
pub struct StartPresentationRequest {
    /// Raw OID4VP authorization request (URL-encoded or JWT).
    pub request: String,
}

#[derive(Debug, Serialize)]
pub struct StartPresentationResponse {
    /// Presentation session ID (prefixed with `prs_`).
    pub session_id: String,
    /// Whether this is a cross-device or same-device flow.
    pub flow: String,
    /// Metadescription ofwhat the verifier is requesting.
    pub client_id: String,
    /// Number of credential query candidates found.
    pub matched_credentials: usize,
}

#[tracing::instrument(skip_all)]
pub async fn start_presentation<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Json(payload): Json<StartPresentationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.request.is_empty() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            error: std::borrow::Cow::Borrowed("invalid_request"),
            error_description: Some("The authorization request must not be empty.".into()),
        });
    }

    let context = state
        .service
        .presentation_engine
        .process_request(&payload.request)
        .await
        .map_err(ApiError::internal)?;

    let credential_views = state
        .service
        .presentation_engine
        .load_credential_views(tenant_id)
        .await
        .map_err(ApiError::internal)?;

    let dcql_result = state
        .service
        .presentation_engine
        .match_credentials(&context, &credential_views);

    let matched = dcql_result
        .candidates
        .values()
        .map(|v| v.len())
        .sum::<usize>();

    let session = PresentationSession::new(tenant_id, context, dcql_result);

    let response = StartPresentationResponse {
        session_id: session.id.clone(),
        flow: format!("{:?}", session.flow).to_lowercase(),
        client_id: session.context.client_id.value().to_string(),
        matched_credentials: matched,
    };

    state
        .service
        .session
        .upsert(session.id.as_str(), &session)
        .await
        .map_err(ApiError::internal)?;

    Ok(ResponseBody::new(StatusCode::CREATED, response))
}
