//! HTTP handler for tenant registration.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::domain::models::tenants::RegisterTenantRequest;
use crate::server::{AppState, error::ApiError, responses::ResponseBody};
use crate::session::SessionStore;

/// Registers a new tenant.
pub async fn register_tenant<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Json(payload): Json<RegisterTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let response = state.tenant_repo.create(payload).await?;
    Ok(ResponseBody::new(StatusCode::CREATED, response))
}
