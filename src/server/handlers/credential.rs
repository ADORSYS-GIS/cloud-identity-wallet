//! HTTP handlers for credential management.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::server::{AppState, error::ApiError};
use crate::session::SessionStore;

/// Deletes a credential owned by the authenticated tenant.
///
/// Verifies tenant ownership by scoping the deletion to both `credential_id`
/// and the `tenant_id` extracted from the bearer token. Returns `404` when the
/// credential does not exist **or** belongs to a different tenant, preventing
/// information leakage about other tenants' credentials.
pub async fn delete_credential<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Path(credential_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .service
        .delete_credential(credential_id, tenant_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
