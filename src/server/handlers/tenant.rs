//! HTTP handler for tenant registration.

use axum::{Json, extract::State, http::StatusCode};

use crate::{
    domain::models::tenants::{
        RegisterTenantRequest, TenantError, TenantErrorResponse, TenantName, TenantResponse,
    },
    server::AppState,
};

/// POST /api/v1/tenants - Register a new tenant.
///
/// This is an unauthenticated endpoint that creates a new tenant record.
/// It serves as the entry point for any new frontend instance.
///
/// # Returns
/// - `201 Created` with `TenantResponse` on success
/// - `400 Bad Request` with `TenantErrorResponse` for validation errors
/// - `500 Internal Server Error` for storage failures
pub async fn register_tenant(
    State(state): State<AppState>,
    Json(payload): Json<RegisterTenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), (StatusCode, Json<TenantErrorResponse>)> {
    // Validate the name before passing to the repository
    let _tenant_name = TenantName::new(&payload.name).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(TenantErrorResponse {
                error: "invalid_request",
                error_description: e,
            }),
        )
    })?;

    // Persist the tenant
    match state.service.tenant_repo.create(payload).await {
        Ok(response) => Ok((StatusCode::CREATED, Json(response))),
        Err(TenantError::InvalidName(msg)) => Err((
            StatusCode::BAD_REQUEST,
            Json(TenantErrorResponse {
                error: "invalid_request",
                error_description: msg,
            }),
        )),
        Err(TenantError::Backend(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TenantErrorResponse {
                error: "server_error",
                error_description: "An internal error occurred while processing your request"
                    .to_string(),
            }),
        )),
    }
}
