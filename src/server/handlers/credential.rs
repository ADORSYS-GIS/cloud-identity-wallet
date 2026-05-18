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
/// Returns `204 No Content` on success. Returns `404 Not Found` if the
/// credential does not exist or is not owned by the requesting tenant.
pub async fn delete_credential<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Path(credential_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .service
        .issuance_engine
        .credential_repo
        .delete(credential_id, tenant_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
