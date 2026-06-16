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
use serde_with::skip_serializing_none;
use url::Url;

use crate::oauth::authorization::OAuthAuthorizationRequest;
use crate::oid4vci::authorization::AuthorizationDetails;
use crate::utils::serialize_json_string;

/// An OAuth 2.0 Authorization Request for OID4VCI.
///
/// Compliant with [OID4VCI §5.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request).
///
/// This struct flattens the standard OAuth 2.0 authorization request parameters
/// from [`OAuthAuthorizationRequest`] and adds OID4VCI-specific extensions.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// REQUIRED. The response type, fixed to `"code"` for Authorization Code flow.
    pub response_type: String,

    /// Standard OAuth 2.0 authorization request parameters.
    #[serde(flatten)]
    pub oauth: OAuthAuthorizationRequest,

    /// OAuth2 resource indicator.
    ///
    /// Must be set to credential_issuer when using the scope parameter and
    /// when the Credential Issuer metadata contains an authorization_servers property.
    pub resource: Option<Url>,

    /// Processing context value originally received in a Credential Offer.
    /// Passed back to the Credential Issuer. See [OID4VCI §5.1.3].
    pub issuer_state: Option<String>,

    /// RAR authorization details requesting specific Credentials.
    /// See [OID4VCI §5.1.1].
    #[serde(serialize_with = "serialize_json_string")]
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
}

impl AuthorizationRequest {
    /// Validates the authorization request per OID4VCI §5.1.
    pub fn validate(&self) -> Result<(), crate::errors::Error> {
        self.oauth.validate_client_id()?;

        // response_type MUST be "code" per OID4VCI §5.1
        if self.response_type != "code" {
            return Err(crate::errors::Error::message(
                crate::errors::ErrorKind::InvalidAuthorizationRequest,
                "'response_type' must be 'code' for OID4VCI authorization code flow",
            ));
        }

        Ok(())
    }
}

/// An OAuth 2.0 Pushed Authorization Request (PAR) as outlined in [OID4VCI §5.1.4].
///
/// [OID4VCI §5.1.4]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest {
    /// The client identifier for the wallet.
    pub client_id: String,
    /// The request URI returned by the authorization server.
    pub request_uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::authorization::CodeChallengeMethod;
    use serde_json::json;

    #[test]
    fn serializes_with_flattened_oauth_fields() {
        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            oauth: OAuthAuthorizationRequest {
                client_id: "my-client".to_string(),
                redirect_uri: Some(Url::parse("https://example.com/callback").unwrap()),
                scope: Some("openid".to_string()),
                state: Some("abc123".to_string()),
                nonce: None,
                code_challenge: Some("challenge123".to_string()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
            },
            resource: None,
            issuer_state: Some("issuer-state-xyz".to_string()),
            authorization_details: None,
        };

        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["response_type"], "code");
        assert_eq!(json["client_id"], "my-client");
        assert_eq!(json["redirect_uri"], "https://example.com/callback");
        assert_eq!(json["scope"], "openid");
        assert_eq!(json["state"], "abc123");
        assert_eq!(json["code_challenge"], "challenge123");
        assert_eq!(json["code_challenge_method"], "S256");
        assert_eq!(json["issuer_state"], "issuer-state-xyz");
    }

    #[test]
    fn deserializes_with_flattened_oauth_fields() {
        let json = json!({
            "response_type": "code",
            "client_id": "my-client",
            "redirect_uri": "https://example.com/callback",
            "scope": "openid",
            "state": "abc123",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "resource": "https://issuer.example.com",
            "issuer_state": "issuer-state-xyz"
        });

        let req: AuthorizationRequest = serde_json::from_value(json).unwrap();

        assert_eq!(req.response_type, "code");
        assert_eq!(req.oauth.client_id, "my-client");
        assert_eq!(
            req.oauth.redirect_uri.unwrap().as_str(),
            "https://example.com/callback"
        );
        assert_eq!(req.oauth.scope.unwrap(), "openid");
        assert_eq!(req.oauth.state.unwrap(), "abc123");
        assert_eq!(req.oauth.code_challenge.unwrap(), "challenge123");
        assert!(
            req.resource
                .unwrap()
                .as_str()
                .starts_with("https://issuer.example.com")
        );
        assert_eq!(req.issuer_state.unwrap(), "issuer-state-xyz");
    }

    #[test]
    fn minimal_request() {
        let json = json!({
            "response_type": "code",
            "client_id": "my-client"
        });

        let req: AuthorizationRequest = serde_json::from_value(json).unwrap();

        assert_eq!(req.response_type, "code");
        assert_eq!(req.oauth.client_id, "my-client");
        assert!(req.oauth.redirect_uri.is_none());
        assert!(req.resource.is_none());
        assert!(req.issuer_state.is_none());
        assert!(req.authorization_details.is_none());
    }
}
