//! HTTP handler for tenant registration.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::{
    domain::models::tenants::{RegisterTenantRequest, TenantError, TenantName},
    server::{AppState, error::ApiError, responses::ResponseBody},
};

/// Registers a new tenant.
pub async fn register_tenant(
    State(state): State<AppState>,
    Json(payload): Json<RegisterTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate the name before passing to the repository
    let tenant_name = TenantName::new(&payload.name).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        error: "invalid_request",
        error_description: Some(e),
    })?;

    // Create a new request with the validated name
    let validated_request = RegisterTenantRequest {
        name: tenant_name.into_inner(),
    };

    let response = state
        .service
        .tenant_repo
        .create(validated_request)
        .await
        .map_err(|e| match e {
            TenantError::InvalidName(msg) => ApiError {
                status: StatusCode::BAD_REQUEST,
                error: "invalid_request",
                error_description: Some(msg),
            },
            TenantError::Backend(source) => ApiError::internal(source),
        })?;

    Ok(ResponseBody::new(StatusCode::CREATED, response))
}
