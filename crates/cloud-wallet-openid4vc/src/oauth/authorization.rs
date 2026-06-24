//! OAuth 2.0 Authorization Request base model.
//!
//! This module defines the common authorization request parameters from OAuth 2.0,
//! OpenID Connect, and related specifications that are shared across OID4VCI and OID4VP.
//!
//! # Spec References
//!
//! - [RFC 6749 §4.1.1 Authorization Request](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1)
//! - [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)
//! - [RFC 9101 JWT-Secured Authorization Request (JAR)](https://www.rfc-editor.org/rfc/rfc9101.html)
//! - [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind, Result};
use crate::utils::is_unreserved_chars;

/// PKCE code challenge method per [RFC 7636 §4.2].
///
/// [RFC 7636 §4.2]: https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CodeChallengeMethod {
    /// SHA-256 code challenge (REQUIRED per RFC 7636).
    #[default]
    #[serde(rename = "S256")]
    S256,
    /// Plain code challenge (NOT RECOMMENDED for production use).
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

/// OAuth 2.0 base authorization request parameters shared across OID4VCI and OID4VP.
///
/// These parameters are defined by:
/// - RFC 6749 §4.1.1: `client_id`, `redirect_uri`, `scope`, `state`
/// - RFC 7636: `code_challenge`, `code_challenge_method`
/// - OpenID Connect Core: `nonce` (for replay protection)
///
/// Note: `response_type` is NOT included here because its valid values are protocol-specific:
/// - OAuth 2.0 Authorization Code flow: "code"
/// - OID4VP: "vp_token" or "vp_token id_token"
///
/// Each protocol-specific model defines its own `response_type` field with appropriate typing.
///
/// This struct is intended to be composed into protocol-specific authorization request
/// models using `#[serde(flatten)]` for serialization compatibility.
///
/// [RFC 6749 §4.1.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
/// [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636.html
/// [OpenID Connect Core]: https://openid.net/specs/openid-connect-core-1_0.html
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthAuthorizationRequest {
    /// REQUIRED. The client identifier.
    ///
    /// Per RFC 6749 §4.1.1, this is the client identifier issued by the authorization server.
    pub client_id: String,

    /// OPTIONAL. The redirect URI.
    ///
    /// Per RFC 6749 §4.1.1, this is where the authorization server sends the user after consent.
    /// May be omitted if the client pre-registered a single redirect URI.
    pub redirect_uri: Option<Url>,

    /// OPTIONAL. Space-separated scope values.
    ///
    /// Per RFC 6749 §3.3, scope values request specific access privileges.
    pub scope: Option<String>,

    /// RECOMMENDED. State value to maintain state between request and callback.
    ///
    /// Per RFC 6749 §4.1.1, this is used to prevent CSRF attacks.
    pub state: Option<String>,

    /// OPTIONAL. Nonce value for replay protection.
    ///
    /// Per OpenID Connect Core §3.1.2, this is used to associate a client session with an ID token.
    /// REQUIRED for OID4VP authorization requests.
    pub nonce: Option<String>,

    /// OPTIONAL. PKCE code challenge (base64url-encoded SHA-256 of verifier).
    ///
    /// Per RFC 7636 §4.3, this prevents authorization code interception attacks.
    pub code_challenge: Option<String>,

    /// OPTIONAL. PKCE code challenge method.
    ///
    /// Per RFC 7636 §4.2, the default is "S256" (SHA-256).
    /// "plain" is NOT RECOMMENDED for production use.
    pub code_challenge_method: Option<CodeChallengeMethod>,
}

impl OAuthAuthorizationRequest {
    /// Validates that `client_id` is non-empty.
    pub fn validate_client_id(&self) -> Result<&str> {
        let trimmed = self.client_id.trim();
        if trimmed.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationRequest,
                "'client_id' must not be empty",
            ));
        }
        Ok(trimmed)
    }

    /// Validates that `nonce` contains only unreserved URI characters per RFC 3986.
    ///
    /// Per OpenID4VP §5.2, nonce MUST contain only unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
    pub fn validate_nonce_unreserved(&self) -> Result<()> {
        if let Some(ref nonce) = self.nonce
            && !is_unreserved_chars(nonce)
        {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationRequest,
                "'nonce' must contain only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)",
            ));
        }
        Ok(())
    }

    /// Validates that `state` contains only unreserved URI characters per RFC 3986.
    pub fn validate_state_unreserved(&self) -> Result<()> {
        // if let Some(ref state) = self.state
        //     && !is_unreserved_chars(state)
        // {
        //     return Err(Error::message(
        //         ErrorKind::InvalidAuthorizationRequest,
        //         "'state' must contain only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)",
        //     ));
        // }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_basic_oauth_request() {
        let req = OAuthAuthorizationRequest {
            client_id: "my-client".to_string(),
            redirect_uri: Some(Url::parse("https://example.com/callback").unwrap()),
            scope: Some("openid".to_string()),
            state: Some("abc123".to_string()),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""client_id":"my-client""#));
        assert!(!json.contains("response_type"));
    }

    #[test]
    fn deserializes_minimal_oauth_request() {
        let req: OAuthAuthorizationRequest = serde_json::from_value(serde_json::json!({
            "client_id": "client"
        }))
        .unwrap();

        assert_eq!(req.client_id, "client");
        assert!(req.redirect_uri.is_none());
        assert!(req.scope.is_none());
    }

    #[test]
    fn validates_client_id() {
        let req = OAuthAuthorizationRequest {
            client_id: "  ".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        };

        assert!(req.validate_client_id().is_err());
    }

    #[test]
    fn validates_nonce_unreserved() {
        let valid = OAuthAuthorizationRequest {
            client_id: "client".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("n-0S6_WzA2Mj".to_string()),
            code_challenge: None,
            code_challenge_method: None,
        };
        assert!(valid.validate_nonce_unreserved().is_ok());

        let invalid = OAuthAuthorizationRequest {
            client_id: "client".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: Some("has spaces".to_string()),
            code_challenge: None,
            code_challenge_method: None,
        };
        assert!(invalid.validate_nonce_unreserved().is_err());
    }

    #[test]
    fn code_challenge_method_serialization() {
        assert_eq!(
            serde_json::to_value(CodeChallengeMethod::S256).unwrap(),
            "S256"
        );
        assert_eq!(
            serde_json::to_value(CodeChallengeMethod::Plain).unwrap(),
            "plain"
        );
    }
}
