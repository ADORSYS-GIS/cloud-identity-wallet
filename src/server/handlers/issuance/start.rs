use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use cloud_wallet_openid4vc::issuance::client::{IssuanceFlow, Oid4vciClient, ResolvedOfferContext};
use tracing::debug;
use uuid::Uuid;

use crate::domain::models::issuance::{
    FlowType, IssuanceError, IssuanceErrorCode, IssuanceStep, StartIssuanceRequest,
    StartIssuanceResponse,
};
use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::{IssuanceSession, SessionStore};

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

async fn start_issuance_session<S: SessionStore>(
    client: &Oid4vciClient,
    session_store: &S,
    offer: &str,
    tenant_id: Uuid,
) -> Result<(ResolvedOfferContext, IssuanceSession, StartIssuanceResponse), IssuanceError> {
    if offer.is_empty() {
        return Err(IssuanceError::new(
            IssuanceErrorCode::InvalidCredentialOffer,
            Some("The credential offer must not be empty.".to_string()),
            IssuanceStep::OfferResolution,
        ));
    }

    debug!(offer = %offer, "resolving credential offer");

    let context = client
        .resolve_offer_with_metadata(offer, None)
        .await
        .map_err(Into::<IssuanceError>::into)?;

    let flow_type = match &context.flow {
        IssuanceFlow::AuthorizationCode { .. } => FlowType::AuthorizationCode,
        IssuanceFlow::PreAuthorizedCode { .. } => FlowType::PreAuthorizedCode,
    };

    let session = IssuanceSession::new(tenant_id, context.clone(), flow_type);

    session_store
        .upsert(session.id.clone(), &session)
        .await
        .map_err(Into::<IssuanceError>::into)?;

    let response = StartIssuanceResponse::from_context(&context, &session)?;

    Ok((context, session, response))
}
