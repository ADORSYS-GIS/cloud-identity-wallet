//! Authorization Request models for OpenID4VCI.
//!
//! This module defines the data structures for OAuth 2.0 authorization requests
//! as extended by OID4VCI (Section 5.1) and RFC 9396 (Rich Authorization Requests).
//!
//! # Spec References
//!
//! - [OID4VCI §5.1 Authorization Request](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request)
//! - [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html)
//! - [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)

use serde::{Deserialize, Serialize};
use url::Url;

use crate::issuance::authorization_detail::AuthorizationDetail;
pub use crate::issuance::authorization_detail::{AuthorizationDetailType, AuthzDetailsClaim};

/// PKCE code challenge method.
///
/// Per [RFC 7636 §4.2], `S256` is REQUIRED and `plain` is OPTIONAL but NOT RECOMMENDED
/// for production use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CodeChallengeMethod {
    /// SHA-256 code challenge (RFC 7636).
    #[default]
    S256,
    /// Plain code challenge (RFC 7636). NOT RECOMMENDED for production use.
    #[serde(rename = "plain")]
    Plain,
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S256 => write!(f, "S256"),
            Self::Plain => write!(f, "plain"),
        }
    }
}

/// An OAuth 2.0 Authorization Request for OID4VCI.
///
/// Compliant with [OID4VCI §5.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Fixed to `"code"` for the Authorization Code flow.
    pub response_type: String,
    /// REQUIRED. The client identifier for the wallet.
    pub client_id: String,
    /// OPTIONAL. The redirect URI where the AS sends the user after consent.
    /// May be omitted if the client pre-registered a single redirect URI.
    pub redirect_uri: Option<Url>,
    /// OPTIONAL. State value to maintain state between request and callback.
    pub state: Option<String>,
    /// OPTIONAL. Scope values requesting Credential issuance (space-separated).
    /// See [OID4VCI §5.1.2].
    pub scope: Option<String>,
    /// OPTIONAL. Processing context value originally received in a Credential Offer.
    /// Passed back to the Credential Issuer. See [OID4VCI §5.1.3].
    pub issuer_state: Option<String>,
    /// OPTIONAL. RAR authorization details requesting specific Credentials.
    /// See [OID4VCI §5.1.1].
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// OPTIONAL. PKCE code challenge (base64url-encoded SHA-256 of the verifier).
    pub code_challenge: Option<String>,
    /// OPTIONAL. PKCE challenge method. Will always be `S256` when present.
    pub code_challenge_method: Option<CodeChallengeMethod>,
}
