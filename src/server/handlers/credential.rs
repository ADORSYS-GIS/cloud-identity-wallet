use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::fmt;
use time::format_description::well_known::Rfc3339;
use url::Url;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialError, CredentialFilter, CredentialFormat, CredentialStatus,
};
use crate::domain::models::credentials::{
    CredentialErrorResponse, CredentialListResponse, CredentialRecord,
};
use crate::server::AppState;
use crate::session::SessionStore;

/// Deserialize a query parameter that may be either a comma-separated string
/// (`?credential_types=A,B`) or a JSON sequence (used in unit tests).
fn deserialize_string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrSeq;

    impl<'de> Visitor<'de> for StringOrSeq {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a comma-separated string or sequence of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect())
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrSeq)
}

/// Query parameters accepted by `GET /api/v1/credentials`.
#[derive(Debug, Deserialize)]
pub struct CredentialListQuery {
    /// Filter by credential configuration IDs. Pass a single value or a
    /// comma-separated list: `?credential_types=A` or `?credential_types=A,B`.
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    pub credential_types: Vec<String>,
    /// Filter by lifecycle status (`active`, `revoked`, `expired`, `suspended`).
    pub status: Option<String>,
    /// Filter by wire format (`dc+sd-jwt`, `mso_mdoc`, etc.).
    pub format: Option<String>,
    /// Filter by issuer URI.
    pub issuer: Option<String>,
}
// helper functions to generate common error responses for credential handlers
fn bad_request(description: impl Into<String>) -> (StatusCode, Json<CredentialErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(CredentialErrorResponse {
            error: "invalid_request",
            error_description: description.into(),
        }),
    )
}

fn internal_error(description: impl Into<String>) -> (StatusCode, Json<CredentialErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(CredentialErrorResponse {
            error: "internal_error",
            error_description: description.into(),
        }),
    )
}

fn not_found() -> (StatusCode, Json<CredentialErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(CredentialErrorResponse {
            error: "credential_not_found",
            error_description: "No credential with that ID exists for the authenticated tenant."
                .to_string(),
        }),
    )
}

/// Format a `UtcDateTime` as an RFC 3339 string.
fn format_utc(dt: time::UtcDateTime) -> Result<String, time::error::Format> {
    dt.format(&Rfc3339)
}

/// Map a domain `Credential` to its HTTP response shape.
fn to_record(c: Credential) -> Result<CredentialRecord, String> {
    let credential_configuration_id = c
        .credential_types
        .into_iter()
        .next()
        .ok_or_else(|| "credential has no credential_types".to_string())?;
    Ok(CredentialRecord {
        id: c.id,
        credential_configuration_id,
        format: c.format.as_str().to_string(),
        issuer: c.issuer,
        status: c.status.as_str().to_string(),
        issued_at: format_utc(c.issued_at).map_err(|e| e.to_string())?,
        expires_at: c
            .valid_until
            .map(format_utc)
            .transpose()
            .map_err(|e| e.to_string())?,
        claims: serde_json::Value::Null,
    })
}

/// `GET /api/v1/credentials` — list credentials for the authenticated tenant.
///
/// Supports optional filters: `status`, `format`, `issuer`, and
/// `credential_types` (repeatable). Returns `400` when `status` or `format`
/// contains an unrecognised value.
pub async fn list_credentials<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Query(params): Query<CredentialListQuery>,
) -> Result<(StatusCode, Json<CredentialListResponse>), (StatusCode, Json<CredentialErrorResponse>)>
{
    let status = params
        .status
        .as_deref()
        .map(|s| {
            s.parse::<CredentialStatus>()
                .map_err(|_| bad_request(format!("invalid status value: '{s}'")))
        })
        .transpose()?;

    let format = params
        .format
        .as_deref()
        .map(|f| {
            f.parse::<CredentialFormat>()
                .map_err(|_| bad_request(format!("invalid format value: '{f}'")))
        })
        .transpose()?;

    let issuer = params
        .issuer
        .as_deref()
        .map(|u| {
            Url::parse(u).map_err(|_| bad_request(format!("invalid issuer URI: '{u}'")))?;
            Ok::<_, (StatusCode, Json<CredentialErrorResponse>)>(u.to_owned())
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
        .credential_repo
        .list(filter)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list credentials for tenant {tenant_id}: {e}");
            internal_error("An internal error occurred while retrieving credentials.")
        })?;

    let records: Vec<CredentialRecord> = credentials
        .into_iter()
        .map(to_record)
        .collect::<Result<_, _>>()
        .map_err(|e| {
            tracing::error!("Failed to format credential timestamp for tenant {tenant_id}: {e}");
            internal_error("An internal error occurred while formatting credential data.")
        })?;

    Ok((
        StatusCode::OK,
        Json(CredentialListResponse {
            credentials: records,
        }),
    ))
}

/// `GET /api/v1/credentials/:id` — retrieve a single credential by wallet ID.
///
/// Returns `404` when no credential with that ID exists for the authenticated
/// tenant (including when the credential belongs to a different tenant).
pub async fn get_credential<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<CredentialRecord>), (StatusCode, Json<CredentialErrorResponse>)> {
    match state
        .service
        .credential_repo
        .find_by_id(id, tenant_id)
        .await
    {
        Ok(credential) => {
            let record = to_record(credential).map_err(|e| {
                tracing::error!(
                    "Failed to format credential {id} timestamp for tenant {tenant_id}: {e}"
                );
                internal_error("An internal error occurred while formatting credential data.")
            })?;
            Ok((StatusCode::OK, Json(record)))
        }
        Err(CredentialError::NotFound { .. }) => Err(not_found()),
        Err(e) => {
            tracing::error!("Failed to retrieve credential {id} for tenant {tenant_id}: {e}");
            Err(internal_error(
                "An internal error occurred while retrieving the credential.",
            ))
        }
    }
}
