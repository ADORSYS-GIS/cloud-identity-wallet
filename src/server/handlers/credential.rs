//! HTTP handlers for credential retrieval endpoints.

use axum::{
    Extension,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialError, CredentialFilter, CredentialFormat, CredentialStatus,
};
use crate::server::{AppState, error::ApiError, responses::ResponseBody};
use crate::session::SessionStore;

/// Query parameters for listing credentials.
#[derive(Debug, Deserialize, Default)]
pub struct ListCredentialsQuery {
    /// Filter by credential configuration IDs (comma-separated or repeated)
    #[serde(rename = "credential_types")]
    pub credential_types: Option<String>,
    /// Filter by status (active, expired, revoked, suspended)
    pub status: Option<String>,
    /// Filter by format (dc+sd-jwt, mso_mdoc, jwt_vc_json, jwt_vc_json-ld, ldp_vc)
    pub format: Option<String>,
    /// Filter by issuer URI
    pub issuer: Option<String>,
}

impl ListCredentialsQuery {
    /// Parse credential types from comma-separated string or repeated params
    fn parse_credential_types(&self) -> Option<Vec<String>> {
        self.credential_types.as_ref().map(|types| {
            types
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
    }
}

/// A credential record in the API response.
#[derive(Debug, Serialize)]
pub struct CredentialRecord {
    /// Internal wallet credential ID (UUID v4)
    pub id: Uuid,
    /// Credential configuration identifier from the issuer's metadata
    #[serde(rename = "credential_configuration_id")]
    pub credential_configuration_id: String,
    /// Credential format
    pub format: String,
    /// Issuer identifier URI
    pub issuer: String,
    /// Current validity status of the credential
    pub status: String,
    /// ISO 8601 timestamp when the credential was issued
    #[serde(rename = "issued_at")]
    pub issued_at: String,
    /// ISO 8601 timestamp when the credential expires (null if no expiry)
    #[serde(rename = "expires_at")]
    pub expires_at: Option<String>,
    /// Decoded credential claims
    pub claims: HashMap<String, serde_json::Value>,
}

impl From<Credential> for CredentialRecord {
    fn from(credential: Credential) -> Self {
        // Parse the credential to extract claims
        let claims = parse_credential_claims(&credential.raw_credential, credential.format);

        Self {
            id: credential.id,
            credential_configuration_id: credential
                .credential_types
                .first()
                .cloned()
                .unwrap_or_default(),
            format: credential.format.as_str().to_string(),
            issuer: credential.issuer,
            status: credential.status.as_str().to_string(),
            issued_at: credential.issued_at.to_string(),
            expires_at: credential.valid_until.map(|t| t.to_string()),
            claims,
        }
    }
}

/// Parse credential claims based on the format.
fn parse_credential_claims(raw_credential: &str, format: CredentialFormat) -> HashMap<String, serde_json::Value> {
    match format {
        CredentialFormat::SdJwtVc => parse_sd_jwt_claims(raw_credential),
        _ => {
            // For other formats, return empty claims for now
            // TODO: Implement parsing for mso_mdoc, jwt_vc_json, etc.
            HashMap::new()
        }
    }
}

/// Parse SD-JWT credential and extract the claims from disclosures.
/// SD-JWT format: header.payload.signature~disclosure1~disclosure2~...
/// Each disclosure is: base64url(JSON_array) where JSON_array = ["salt", "claim_name", "claim_value"]
fn parse_sd_jwt_claims(raw_credential: &str) -> HashMap<String, serde_json::Value> {
    tracing::debug!("Parsing SD-JWT credential, length: {}", raw_credential.len());
    
    // Split by "~" to separate the JWT from the disclosures
    let parts: Vec<&str> = raw_credential.split('~').collect();
    tracing::debug!("SD-JWT has {} parts (1 JWT + {} disclosures)", parts.len(), parts.len().saturating_sub(1));
    
    if parts.len() <= 1 {
        // No disclosures, return empty claims
        tracing::debug!("No disclosures found in SD-JWT");
        return HashMap::new();
    }

    // Parse disclosures (skip the first part which is the JWT)
    let mut claims = HashMap::new();
    for (idx, disclosure) in parts[1..].iter().enumerate() {
        tracing::debug!("Parsing disclosure {}: {}", idx, &disclosure[..disclosure.len().min(20)]);
        if let Some((name, value)) = parse_disclosure(disclosure) {
            tracing::debug!("Successfully parsed claim: {} = {:?}", name, value);
            claims.insert(name, value);
        } else {
            tracing::warn!("Failed to parse disclosure {}", idx);
        }
    }

    tracing::debug!("Extracted {} claims from SD-JWT", claims.len());
    claims
}

/// Parse a single SD-JWT disclosure.
/// Disclosure format: base64url(JSON_array) where JSON_array = ["salt", "claim_name", "claim_value"]
/// Returns (claim_name, claim_value) if successfully parsed.
fn parse_disclosure(disclosure: &str) -> Option<(String, serde_json::Value)> {
    // Decode base64url
    let decoded = decode_base64url(disclosure)?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    tracing::debug!("Decoded disclosure: {}", decoded_str);

    // Parse as JSON array: ["salt", "claim_name", "claim_value"]
    let json_array: Vec<serde_json::Value> = serde_json::from_str(&decoded_str).ok()?;
    
    if json_array.len() != 3 {
        tracing::warn!("Disclosure JSON array has {} elements, expected 3", json_array.len());
        return None;
    }

    let name = json_array[1].as_str()?.to_string();
    let value = json_array[2].clone();

    tracing::debug!("Parsed claim: {} = {:?}", name, value);
    Some((name, value))
}

/// Decode a base64url string to bytes.
fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    // Add padding if necessary
    let padding_needed = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding_needed));

    // Replace base64url characters with standard base64
    let standard_b64 = padded.replace('-', "+").replace('_', "/");

    // Decode base64
    general_purpose::STANDARD.decode(&standard_b64).ok()
}


/// Response body for listing credentials.
#[derive(Debug, Serialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialRecord>,
}

/// Lists all credentials for the authenticated tenant.
///
/// Supports optional query-parameter filters for status, format, issuer, and credential types.
/// Unknown status or format values return 400 Bad Request.
pub async fn list_credentials<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Query(query): Query<ListCredentialsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate status parameter if provided
    let status = if let Some(ref status_str) = query.status {
        Some(
            CredentialStatus::from_str(status_str).map_err(|_| ApiError {
                status: StatusCode::BAD_REQUEST,
                error: std::borrow::Cow::Borrowed("invalid_request"),
                error_description: Some(format!("Unknown status value: {}", status_str)),
            })?,
        )
    } else {
        None
    };

    // Validate format parameter if provided
    let format = if let Some(ref format_str) = query.format {
        Some(
            CredentialFormat::from_str(format_str).map_err(|_| ApiError {
                status: StatusCode::BAD_REQUEST,
                error: std::borrow::Cow::Borrowed("invalid_request"),
                error_description: Some(format!("Unknown format value: {}", format_str)),
            })?,
        )
    } else {
        None
    };

    let filter = CredentialFilter {
        tenant_id: Some(tenant_id),
        credential_types: query.parse_credential_types(),
        status,
        format,
        issuer: query.issuer.clone(),
        subject: None,
        exclude_expired: false,
    };

    // Get credentials from the repository
    let credentials = state
        .service
        .credential_repo
        .list(filter)
        .await
        .map_err(|e| ApiError::internal(e))?;

    let response = CredentialListResponse {
        credentials: credentials.into_iter().map(CredentialRecord::from).collect(),
    };

    Ok(ResponseBody::new(StatusCode::OK, response))
}

/// Retrieves a single credential by its ID.
///
/// Returns 404 if the credential doesn't exist or belongs to a different tenant.
pub async fn get_credential<S: SessionStore>(
    State(state): State<AppState<S>>,
    Extension(tenant_id): Extension<Uuid>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    // Get credential from the repository
    let credential = state
        .service
        .credential_repo
        .find_by_id(id, tenant_id)
        .await
        .map_err(|e| match e {
            CredentialError::NotFound { .. } => ApiError {
                status: StatusCode::NOT_FOUND,
                error: std::borrow::Cow::Borrowed("credential_not_found"),
                error_description: Some(
                    "No credential with that ID exists for the authenticated tenant.".into(),
                ),
            },
            _ => ApiError::internal(e),
        })?;

    let response: CredentialRecord = credential.into();

    Ok(ResponseBody::new(StatusCode::OK, response))
}
