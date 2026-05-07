use std::borrow::Cow;

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use time::format_description::well_known::Rfc3339;
use url::Url;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialError, CredentialFilter, CredentialFormat, CredentialStatus,
};
use crate::domain::models::issuance::{
    CredentialListQuery, CredentialListResponse, CredentialRecord,
};
use crate::server::AppState;
use crate::server::error::ApiError;
use crate::server::responses::ResponseBody;
use crate::session::SessionStore;

/// Format a `UtcDateTime` as an RFC 3339 string.
fn format_utc(dt: time::UtcDateTime) -> Result<String, time::error::Format> {
    dt.format(&Rfc3339)
}

/// Map a domain `Credential` to its HTTP response shape.
fn to_record(c: Credential) -> Result<CredentialRecord, ApiError> {
    let credential_configuration_id = c
        .credential_types
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::internal("credential has no credential_types"))?;
    Ok(CredentialRecord {
        id: c.id,
        credential_configuration_id,
        format: c.format.as_str().to_string(),
        issuer: c.issuer,
        status: c.status.as_str().to_string(),
        issued_at: format_utc(c.issued_at).map_err(ApiError::internal)?,
        expires_at: c
            .valid_until
            .map(format_utc)
            .transpose()
            .map_err(ApiError::internal)?,
        claims: serde_json::Value::Null,
    })
}

/// `GET /api/v1/credentials` — list credentials for the authenticated tenant.
pub async fn list_credentials<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Query(params): Query<CredentialListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let status = params
        .status
        .as_deref()
        .map(|s| {
            s.parse::<CredentialStatus>().map_err(|_| ApiError {
                status: StatusCode::BAD_REQUEST,
                error: Cow::Borrowed("invalid_request"),
                error_description: Some(format!("invalid status value: '{s}'")),
            })
        })
        .transpose()?;

    let format = params
        .format
        .as_deref()
        .map(|f| {
            f.parse::<CredentialFormat>().map_err(|_| ApiError {
                status: StatusCode::BAD_REQUEST,
                error: Cow::Borrowed("invalid_request"),
                error_description: Some(format!("invalid format value: '{f}'")),
            })
        })
        .transpose()?;

    let issuer = params
        .issuer
        .as_deref()
        .map(|u| {
            Url::parse(u).map_err(|_| ApiError {
                status: StatusCode::BAD_REQUEST,
                error: Cow::Borrowed("invalid_request"),
                error_description: Some(format!("invalid issuer URI: '{u}'")),
            })?;
            Ok::<_, ApiError>(u.to_owned())
        })
        .transpose()?;

    let filter = CredentialFilter {
        tenant_id: Some(tenant_id),
        credential_types: if params.credential_types.is_empty() {
            None
        } else {
            Some(params.credential_types)
        },
        status,
        format,
        issuer,
        ..CredentialFilter::default()
    };

    let credentials = state
        .service
        .issuance_engine
        .credential_repo
        .list(filter)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list credentials for tenant {tenant_id}: {e}");
            ApiError::internal(e)
        })?;

    let records = credentials
        .into_iter()
        .map(to_record)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ResponseBody::new(
        StatusCode::OK,
        CredentialListResponse {
            credentials: records,
        },
    ))
}

/// `GET /api/v1/credentials/:id` — retrieve a single credential by wallet ID.
pub async fn get_credential<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let credential = state
        .service
        .issuance_engine
        .credential_repo
        .find_by_id(id, tenant_id)
        .await
        .map_err(|e| match e {
            CredentialError::NotFound { .. } => ApiError {
                status: StatusCode::NOT_FOUND,
                error: Cow::Borrowed("credential_not_found"),
                error_description: Some(
                    "No credential with that ID exists for the authenticated tenant.".into(),
                ),
            },
            other => {
                tracing::error!(
                    "Failed to retrieve credential {id} for tenant {tenant_id}: {other}"
                );
                ApiError::internal(other)
            }
        })?;

    let record = to_record(credential)?;
    Ok(ResponseBody::new(StatusCode::OK, record))
}
