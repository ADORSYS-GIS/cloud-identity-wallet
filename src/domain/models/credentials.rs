use serde::Serialize;
use uuid::Uuid;

/// Response body for a single verifiable credential stored in the wallet.
///
/// `claims` is always `null` in the current implementation; format-specific
/// claim decoding will be added in a future iteration.
#[derive(Debug, Serialize)]
pub struct CredentialRecord {
    pub id: Uuid,
    pub credential_configuration_id: String,
    pub format: String,
    pub issuer: String,
    pub status: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Decoded credential claims. Format-specific parsing is out of scope for
    /// this implementation; field is always `null`.
    pub claims: serde_json::Value,
}

/// Response body for `GET /api/v1/credentials`.
#[derive(Debug, Serialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialRecord>,
}

/// RFC 7807 / OID4VCI error response body for credential operations.
#[derive(Debug, Serialize)]
pub struct CredentialErrorResponse {
    pub error: &'static str,
    pub error_description: String,
}
