//! HTTP handler for tenant registration.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::domain::models::tenants::RegisterTenantRequest;
use crate::server::{AppState, error::ApiError, responses::ResponseBody};

/// Registers a new tenant.
pub async fn register_tenant(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let response = state.tenant_repo.create(payload).await?;
    Ok(ResponseBody::new(StatusCode::CREATED, response))
}
