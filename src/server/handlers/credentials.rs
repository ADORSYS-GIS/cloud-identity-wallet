use axum::{
    extract::{Extension, Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_qs::{Config, DuplicateKeyBehavior};
use std::{borrow::Cow, sync::OnceLock};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialFilter, CredentialListResponse, CredentialRecord,
};
use crate::server::error::ApiError;
use crate::server::{AppState, responses::ResponseBody};
use crate::session::SessionStore;

/// List credential summaries for the authenticated tenant.
///
/// Returns display metadata for each credential, suitable for
/// rendering the credential list / home screen.
pub async fn list_credentials<S: SessionStore + Clone>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    RawQuery(raw_query): RawQuery,
) -> Result<impl IntoResponse, ApiError> {
    let mut filter = deserialize_filter(raw_query.as_deref())?;
    filter.tenant_id = Some(tenant_id);

    let credentials = state
        .service
        .issuance_engine
        .credential_repo
        .list(filter)
        .await?;

    let response = CredentialListResponse { credentials };
    Ok(ResponseBody::new(StatusCode::OK, response))
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
        .await?;

    let record = to_record(credential)?;
    Ok(ResponseBody::new(StatusCode::OK, record))
}

fn deserialize_filter(query: Option<&str>) -> Result<CredentialFilter, ApiError> {
    let Some(query) = query else {
        return Ok(CredentialFilter::default());
    };

    (*query_config())
        .deserialize_str(query)
        .map_err(|error| invalid_query(format!("invalid credentials filter query: {error}")))
}

fn query_config() -> &'static Config {
    static QUERY_CONFIG: OnceLock<Config> = OnceLock::new();
    QUERY_CONFIG.get_or_init(|| {
        Config::new()
            .use_form_encoding(true)
            .duplicate_key_behavior(DuplicateKeyBehavior::Error)
    })
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

/// Format a `UtcDateTime` as an RFC 3339 string.
fn format_utc(dt: time::UtcDateTime) -> Result<String, time::error::Format> {
    dt.format(&Rfc3339)
}

fn invalid_query(description: impl Into<String>) -> ApiError {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        error: Cow::Borrowed("invalid_request"),
        error_description: Some(description.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::credential::{CredentialFormat, CredentialStatus};

    #[test]
    fn parses_credential_filters() {
        let filter = deserialize_filter(Some(
            "credential_types=eu.europa.ec.eudi.pid.1,EmployeeBadge&\
             credential_types=VerifiableCredential&\
             status=active&format=dc%2Bsd-jwt&issuer=https%3A%2F%2Fissuer.example.eu",
        ))
        .unwrap();

        assert_eq!(
            filter.credential_types,
            Some(vec![
                "eu.europa.ec.eudi.pid.1".to_string(),
                "EmployeeBadge".to_string(),
                "VerifiableCredential".to_string(),
            ])
        );
        assert_eq!(filter.status, Some(CredentialStatus::Active));
        assert_eq!(filter.format, Some(CredentialFormat::SdJwtVc));
        assert_eq!(filter.issuer, Some("https://issuer.example.eu".to_string()));
    }

    #[test]
    fn builds_tenant_scoped_filter() {
        let tenant_id = Uuid::new_v4();
        let mut filter = deserialize_filter(Some(
            "credential_types=EmployeeBadge&status=revoked&format=jwt_vc_json&issuer=did%3Aexample%3Aissuer",
        ))
        .unwrap();
        filter.tenant_id = Some(tenant_id);

        assert_eq!(filter.tenant_id, Some(tenant_id));
        assert_eq!(
            filter.credential_types,
            Some(vec!["EmployeeBadge".to_string()])
        );
        assert_eq!(filter.status, Some(CredentialStatus::Revoked));
        assert_eq!(filter.format, Some(CredentialFormat::JwtVcJson));
        assert_eq!(filter.issuer, Some("did:example:issuer".to_string()));
    }

    #[test]
    fn rejects_invalid_enum_filters() {
        let error = deserialize_filter(Some("status=unknown")).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.error, "invalid_request");
    }

    #[test]
    fn rejects_duplicate_single_value_filters() {
        let error = deserialize_filter(Some("format=dc%2Bsd-jwt&format=mso_mdoc")).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.error, "invalid_request");
        assert!(error.error_description.is_some());
    }
}
