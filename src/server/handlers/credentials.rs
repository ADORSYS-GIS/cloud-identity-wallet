use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use uuid::Uuid;

use crate::domain::models::credential::{CredentialFilter, CredentialSummary};
use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::SessionStore;

#[derive(Debug, Serialize)]
struct CredentialListResponse {
    pub credentials: Vec<CredentialSummary>,
}

/// List credential summaries for the authenticated tenant.
///
/// Returns display metadata for each credential, suitable for
/// rendering the credential list / home screen.
pub async fn list_credentials<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let filter = CredentialFilter {
        tenant_id: Some(tenant_id),
        ..Default::default()
    };

    let credentials = state
        .service
        .issuance_engine
        .credential_repo
        .list(filter)
        .await?;

    let response = CredentialListResponse { credentials };
    Ok(ResponseBody::new(StatusCode::OK, response))
}
