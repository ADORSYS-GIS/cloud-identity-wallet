use std::collections::HashMap;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::models::credential::CredentialFormat;
use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::{PresentationSession, SessionStore};

#[derive(Debug, Deserialize)]
pub struct StartPresentationRequest {
    /// Raw OID4VP authorization request (URL-encoded or JWT).
    pub request: String,
}

#[derive(Debug, Serialize)]
pub struct StartPresentationResponse {
    /// Presentation session ID (prefixed with `prs_`).
    pub session_id: String,
    /// Whether this is a cross-device or same-device flow.
    pub flow: String,
    /// Metadescription ofwhat the verifier is requesting.
    pub client_id: String,
    /// Number of credential query candidates found.
    pub matched_credentials: usize,
    /// Per-credential rendered claims for the matched candidates.
    ///
    /// Keys are credential IDs from the DCQL match results. Values are
    /// namespaced JSON objects. For mdoc credentials, binary payloads are
    /// redacted to `null`; use the typed `claims_view` on the credential
    /// detail endpoint for safe binary metadata.
    pub disclosed_claims: HashMap<String, serde_json::Value>,
}

#[tracing::instrument(skip_all)]
pub async fn start_presentation<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Json(payload): Json<StartPresentationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.request.is_empty() {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            error: std::borrow::Cow::Borrowed("invalid_request"),
            error_description: Some("The authorization request must not be empty.".into()),
        });
    }

    let context = state
        .service
        .presentation_engine
        .process_request(&payload.request)
        .await
        .map_err(ApiError::internal)?;

    let credential_views = state
        .service
        .presentation_engine
        .load_credential_views(tenant_id)
        .await
        .map_err(ApiError::internal)?;

    let dcql_result = state
        .service
        .presentation_engine
        .match_credentials(&context, &credential_views);

    let matched = dcql_result
        .candidates
        .values()
        .map(|v| v.len())
        .sum::<usize>();

    let disclosed_claims = render_disclosed_claims(&state, tenant_id, &dcql_result)
        .await
        .unwrap_or_default();

    let session = PresentationSession::new(tenant_id, context, dcql_result);

    let response = StartPresentationResponse {
        session_id: session.id.clone(),
        flow: format!("{:?}", session.flow).to_lowercase(),
        client_id: session.context.client_id.value().to_string(),
        matched_credentials: matched,
        disclosed_claims,
    };

    state
        .service
        .session
        .upsert(session.id.as_str(), &session)
        .await
        .map_err(ApiError::internal)?;

    Ok(ResponseBody::new(StatusCode::CREATED, response))
}

/// Renders claim values for every credential referenced in the DCQL match
/// results, keyed by credential ID.
///
/// For mdoc credentials, claims are rendered via
/// [`ParsedMdoc::to_safe_claims`] (binary payloads redacted to `null`).
/// For SD-JWT VC credentials, claims are rendered via
/// [`SdJwt::to_rendered_claims`].
async fn render_disclosed_claims<S: SessionStore + Clone>(
    state: &AppState<S>,
    tenant_id: Uuid,
    dcql_result: &cloud_wallet_openid4vc::oid4vp::selection::SelectionResult,
) -> Result<HashMap<String, serde_json::Value>, ApiError> {
    use cloud_wallet_openid4vc::formats::mdoc::ParsedMdoc;
    use cloud_wallet_openid4vc::formats::sd_jwt::SdJwt;

    let preferred_locales = state
        .service
        .presentation_engine
        .preferred_display_locales();
    let mut claims_map = HashMap::new();

    for candidates in dcql_result.candidates.values() {
        for candidate in candidates {
            let credential_id = &candidate.credential_id;
            if claims_map.contains_key(credential_id) {
                continue;
            }

            let Ok(uuid) = Uuid::parse_str(credential_id) else {
                continue;
            };

            let Ok(credential) = state
                .service
                .presentation_engine
                .credential_repo
                .find_by_id(uuid, tenant_id)
                .await
            else {
                continue;
            };

            let rendered = match credential.format {
                CredentialFormat::SdJwtVc => SdJwt::parse(&credential.raw_credential)
                    .and_then(|sd_jwt| sd_jwt.to_rendered_claims())
                    .map_err(|e| {
                        ApiError::internal(format!(
                            "failed to render SD-JWT VC claims for credential {credential_id}: {e}"
                        ))
                    })
                    .ok(),
                CredentialFormat::Mdoc => ParsedMdoc::parse(&credential.raw_credential)
                    .map(|mdoc| mdoc.to_rendered_claims_with_display(&[], preferred_locales))
                    .map_err(|e| {
                        ApiError::internal(format!(
                            "failed to render mdoc claims for credential {credential_id}: {e}"
                        ))
                    })
                    .ok(),
                _ => None,
            };

            if let Some(value) = rendered {
                claims_map.insert(credential_id.clone(), value);
            }
        }
    }

    Ok(claims_map)
}
