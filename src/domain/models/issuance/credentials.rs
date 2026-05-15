use serde::{Deserialize, Serialize};
use serde_with::{StringWithSeparator, formats::CommaSeparator, serde_as};
use uuid::Uuid;

/// Query parameters accepted by `GET /api/v1/credentials`.
#[serde_as]
#[derive(Debug, Deserialize)]
pub struct CredentialListQuery {
    /// Filter by credential configuration IDs. Pass a single value or a
    /// comma-separated list: `?credential_types=A` or `?credential_types=A,B`.
    #[serde(default)]
    #[serde_as(as = "StringWithSeparator<CommaSeparator, String>")]
    pub credential_types: Vec<String>,
    /// Filter by lifecycle status (`active`, `revoked`, `expired`, `suspended`).
    pub status: Option<String>,
    /// Filter by wire format (`dc+sd-jwt`, `mso_mdoc`, etc.).
    pub format: Option<String>,
    /// Filter by issuer URI.
    pub issuer: Option<String>,
}

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
