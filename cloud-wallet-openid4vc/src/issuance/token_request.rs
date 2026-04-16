//! Token Request models.
//!
//! Spec references:
//! - OpenID4VCI §6.1: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request>
//! - RFC 6749 §4.1.3 (Authorization Code): <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3>
//! - RFC 7636 (PKCE): <https://www.rfc-editor.org/rfc/rfc7636>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use super::authz_details::AuthorizationDetails;

/// Token Request as defined in OpenID4VCI §6.1.
///
/// OpenID4VCI defines two grant types for credential issuance:
/// - `authorization_code`: Standard OAuth 2.0 authorization code flow
/// - `urn:ietf:params:oauth:grant-type:pre-authorized_code`: Pre-authorized code flow
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthorizationCode(AuthorizationCodeRequest),

    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(PreAuthorizedCodeRequest),
}

/// Authorization Code token request per RFC 6749 §4.1.3.
///
/// Required: `code`
/// Conditional: `redirect_uri` (REQUIRED if included in authorization request),
///             `client_id` (REQUIRED if client not authenticating per §3.2.1)
/// Optional: `code_verifier` (PKCE per RFC 7636), `authorization_details` (RFC 9396)
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRequest {
    /// The authorization code received from the authorization server (REQUIRED).
    pub code: String,
    /// REQUIRED if included in the authorization request; values must be identical.
    pub redirect_uri: Option<Url>,
    /// REQUIRED if the client is not authenticating with the authorization server.
    pub client_id: String,
    /// PKCE code verifier per RFC 7636.
    pub code_verifier: Option<String>,
    /// Authorization details per RFC 9396 for fine-grained credential requests.
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
}

/// Pre-Authorized Code token request per OpenID4VCI §6.1.
///
/// Required: `pre-authorized_code`
/// Conditional: `tx_code` (MUST be present if tx_code was in credential offer)
/// Optional: `authorization_details` (RFC 9396)
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAuthorizedCodeRequest {
    /// The code representing the authorization to obtain Credentials (REQUIRED).
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// OAuth2 client_id.
    ///
    /// REQUIRED unless the AS explicitly allows anonymous pre-authorized code access.
    pub client_id: Option<String>,
    /// Transaction code; MUST be present if tx_code object was in the Credential Offer.
    pub tx_code: Option<String>,
    /// Authorization details per RFC 9396 for requesting specific credential configurations.
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_authorization_code_request_example() {
        let request = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            redirect_uri: Some(Url::parse("https://wallet.example.org/cb").unwrap()),
            client_id: "https://client.example.org/cb".to_string(),
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
            authorization_details: None,
        });

        let json = serde_json::to_value(&request).expect("serialize failed");
        assert_eq!(json["grant_type"], "authorization_code");
        assert_eq!(json["code"], "SplxlOBeZQQYbYS6WxSbIA");
        assert_eq!(
            json["code_verifier"],
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert_eq!(json["redirect_uri"], "https://wallet.example.org/cb");
    }

    #[test]
    fn spec_pre_authorized_code_request_example() {
        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            client_id: None,
            tx_code: Some("493536".to_string()),
            authorization_details: Some(vec![AuthorizationDetails::for_configuration(
                "UniversityDegreeCredential",
            )]),
        });

        let json = serde_json::to_value(&request).expect("serialize failed");
        assert_eq!(
            json["grant_type"],
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        );
        assert_eq!(json["pre-authorized_code"], "SplxlOBeZQQYbYS6WxSbIA");
        assert_eq!(json["tx_code"], "493536");
    }

    #[test]
    fn pre_authorized_code_key_uses_hyphen() {
        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "abc".to_string(),
            client_id: None,
            tx_code: None,
            authorization_details: None,
        });

        let json_str = serde_json::to_string(&request).expect("serialize failed");
        assert!(json_str.contains(r#""pre-authorized_code":"abc""#));
    }

    #[test]
    fn pre_authorized_code_request_roundtrip_with_authorization_details() {
        // RFC 9396 authorization_details round-trip test
        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            client_id: None,
            tx_code: Some("493536".to_string()),
            authorization_details: Some(vec![AuthorizationDetails::for_configuration(
                "UniversityDegreeCredential",
            )]),
        });

        let json = serde_json::to_string(&request).expect("serialize failed");
        let roundtripped: TokenRequest = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(request, roundtripped);
    }

    #[test]
    fn deser_fails_on_missing_required_field_auth_code() {
        let json = r#"{"grant_type": "authorization_code"}"#;
        let result: Result<TokenRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn deser_fails_on_missing_required_field_pre_auth() {
        let json = r#"{"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code"}"#;
        let result: Result<TokenRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
