use axum::{
    extract::{Extension, Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
};
use cloud_wallet_openid4vc::formats::sd_jwt::SdJwt;
use serde_qs::{Config, DuplicateKeyBehavior};
use std::{borrow::Cow, sync::OnceLock};
use url::Url;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialFilter, CredentialFormat, CredentialListResponse,
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

    let claims = render_claims(&credential)?;
    Ok(ResponseBody::new(StatusCode::OK, claims))
}

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

fn deserialize_filter(query: Option<&str>) -> Result<CredentialFilter, ApiError> {
    let Some(query) = query else {
        return Ok(CredentialFilter::default());
    };

    let filter: CredentialFilter = (*query_config())
        .deserialize_str(query)
        .map_err(|error| invalid_query(format!("invalid credentials filter query: {error}")))?;

    // Validate issuer is a valid URI if provided
    if let Some(ref issuer) = filter.issuer
        && Url::parse(issuer).is_err()
    {
        return Err(invalid_query("issuer must be a valid URI"));
    }
    Ok(filter)
}

fn query_config() -> &'static Config {
    static QUERY_CONFIG: OnceLock<Config> = OnceLock::new();
    QUERY_CONFIG.get_or_init(|| {
        Config::new()
            .use_form_encoding(true)
            .duplicate_key_behavior(DuplicateKeyBehavior::Error)
    })
}

fn render_claims(c: &Credential) -> Result<serde_json::Value, ApiError> {
    match c.format {
        CredentialFormat::SdJwtVc => SdJwt::parse(&c.raw_credential)
            .and_then(|sd_jwt| sd_jwt.to_rendered_claims())
            .map_err(|error| {
                ApiError::internal(format!("failed to parse stored SD-JWT VC claims: {error}"))
            }),
        _ => Ok(serde_json::Value::Null),
    }
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn b64(value: serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).expect("test JSON should serialize"))
    }

    fn compact_jwt(header: serde_json::Value, claims: serde_json::Value) -> String {
        format!("{}.{}.sig", b64(header), b64(claims))
    }

    fn raw_sd_jwt() -> String {
        let jwt = compact_jwt(
            serde_json::json!({ "alg": "ES256", "typ": "dc+sd-jwt" }),
            serde_json::json!({
                "iss": "https://issuer.example.com",
                "sub": "did:example:subject",
                "iat": 1_683_000_000,
                "exp": 1_883_000_000,
                "vct": "eu.europa.ec.eudi.pid.1",
                "given_name": "Ada",
                "family_name": "Lovelace",
                "address": {
                    "locality": "London"
                }
            }),
        );
        format!("{jwt}~")
    }

    fn credential(raw_credential: String) -> Credential {
        Credential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            issuer: "https://issuer.example.com".to_string(),
            subject: Some("did:example:subject".to_string()),
            credential_types: vec!["eu.europa.ec.eudi.pid.1".to_string()],
            format: CredentialFormat::SdJwtVc,
            external_id: None,
            status: CredentialStatus::Active,
            issued_at: time::UtcDateTime::now(),
            valid_until: None,
            is_revoked: false,
            status_location: None,
            status_index: None,
            raw_credential,
        }
    }

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

    #[test]
    fn renders_sd_jwt_claims_without_reverification() {
        let claims = render_claims(&credential(raw_sd_jwt())).expect("claims should render");

        assert_eq!(claims["given_name"], "Ada");
        assert_eq!(claims["family_name"], "Lovelace");
        assert_eq!(claims["address"]["locality"], "London");
        assert!(claims.get("iss").is_none());
        assert!(claims.get("sub").is_none());
        assert!(claims.get("iat").is_none());
        assert!(claims.get("exp").is_none());
        assert!(claims.get("vct").is_none());
    }
}
