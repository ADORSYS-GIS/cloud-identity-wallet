//! HTTP handler for tenant registration.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::domain::models::tenants::{
    RegisterTenantRequest, TenantError, TenantErrorResponse, TenantName,
};
use crate::server::AppState;
use crate::session::SessionStore;

/// Registers a new tenant.
pub async fn register_tenant<S: SessionStore>(
    State(state): State<AppState<S>>,
    Json(payload): Json<RegisterTenantRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<TenantErrorResponse>)> {
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
