use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::domain::models::issuance::StartIssuanceRequest;
use crate::domain::models::issuance::start_issuance_session;
use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::SessionStore;

pub async fn start_issuance<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Json(payload): Json<StartIssuanceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (_, _, response) = start_issuance_session(
        &state.service.issuance_engine.client,
        &state.service.session,
        &payload.offer,
        tenant_id,
    )
    .await?;

    Ok(ResponseBody::new(StatusCode::CREATED, response))
}
