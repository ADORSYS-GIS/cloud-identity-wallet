use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::debug;
use uuid::Uuid;

use crate::domain::models::presentation::{
    PresentationError, PresentationErrorCode, StartPresentationRequest, StartPresentationResponse,
};
use crate::server::AppState;
use crate::server::error::ApiError;
use crate::server::responses::ResponseBody;
use crate::session::{PresentationSession, SessionStore};

/// Starts a presentation flow by processing a raw OID4VP authorization request.
///
/// Validates and resolves the request, matches the tenant's stored credentials
/// against the DCQL query, creates a session, and returns the consent screen
/// payload.
pub async fn start_presentation<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Json(payload): Json<StartPresentationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    debug!("processing presentation start request");

    let context = state
        .service
        .presentation_engine
        .process_request(&payload.request)
        .await?;
    validate_origin(payload.origin.as_deref(), &context.request.expected_origins)?;
    state
        .service
        .presentation_engine
        .ensure_supported_vp_formats(&context)?;

    let (credentials, credential_displays) = state
        .service
        .presentation_engine
        .load_credential_views(tenant_id)
        .await?;

    let dcql_result = state
        .service
        .presentation_engine
        .match_credentials(&context, &credentials);

    if !dcql_result.satisfies_query {
        return Err(PresentationError::new(
            PresentationErrorCode::NoMatchingCredentials,
            "No stored credentials match the verifier's DCQL query",
        )
        .into());
    }

    let session = PresentationSession::new(tenant_id, context, dcql_result);
    let expires_at = (OffsetDateTime::now_utc() + state.service.session.ttl())
        .format(&Rfc3339)
        .map_err(|e| {
            PresentationError::internal_message(format!(
                "failed to format expiration timestamp: {e}"
            ))
        })?;

    state
        .service
        .session
        .upsert(session.id.clone(), &session)
        .await?;

    let response =
        StartPresentationResponse::from_session(&session, &credential_displays, expires_at)?;

    Ok(ResponseBody::new(StatusCode::CREATED, response))
}

fn validate_origin(
    origin: Option<&str>,
    expected_origins: &Option<Vec<String>>,
) -> Result<(), PresentationError> {
    let Some(expected_origins) = expected_origins else {
        return Ok(());
    };

    let Some(origin) = origin else {
        return Err(PresentationError::new(
            PresentationErrorCode::InvalidRequest,
            "origin is required when expected_origins is present",
        ));
    };

    if expected_origins.iter().any(|expected| expected == origin) {
        return Ok(());
    }

    Err(PresentationError::new(
        PresentationErrorCode::InvalidRequest,
        "origin does not match expected_origins",
    ))
}
