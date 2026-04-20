use serde::Serialize;

use crate::issuance::client::error::ClientError;

/// Builds a holder-binding proof JWT for a credential request.
#[async_trait::async_trait]
pub trait ProofSigner: Send + Sync + 'static {
    /// Sign `payload` and return the compact JWT string.
    async fn sign_proof(&self, claims: ProofClaims) -> Result<String, ClientError>;
}

/// Claims for an `openid4vci-proof+jwt` proof JWT.
#[derive(Debug, Clone, Serialize)]
pub struct ProofClaims {
    /// Audience: the `credential_issuer` URL from issuer metadata.
    pub aud: String,
    /// Issued-at (Unix epoch seconds).
    pub iat: i64,
    /// `client_id` of the Client making the request.
    /// Optional for Pre-Authorized Code Flow with anonymous access to the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Nonce from the issuer, bound to this request.
    /// Must be present when the issuer has a nonce endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}
