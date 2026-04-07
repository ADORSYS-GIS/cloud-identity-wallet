//! Token Request models.
//!
//! Spec references:
//! - OpenID4VCI §6.1: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request>
//! - RFC 6749 §4.1.3 (Authorization Code): <https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3>
//! - RFC 6749 §6 (Refresh Token): <https://www.rfc-editor.org/rfc/rfc6749#section-6>
//! - RFC 7636 (PKCE): <https://www.rfc-editor.org/rfc/rfc7636>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Token Request as defined in [OID4VCI §6.1] and [RFC 6749 §4.1.3].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthorizationCode(AuthorizationCodeRequest),

    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(PreAuthorizedCodeRequest),

    /// Refresh token grant per RFC 6749 §6.
    #[serde(rename = "refresh_token")]
    RefreshToken(RefreshTokenRequest),
}

/// Authorization Code token request per RFC 6749 §4.1.3.
///
/// Required: `code`
/// Conditional: `redirect_uri` (REQUIRED if included in authorization request),
///             `client_id` (REQUIRED if client not authenticating per §3.2.1)
/// Optional: `code_verifier` (PKCE per RFC 7636), `scope`, `authorization_details` (RFC 9396)
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRequest {
    /// The authorization code received from the authorization server (REQUIRED).
    pub code: String,
    /// REQUIRED if included in the authorization request; values must be identical.
    pub redirect_uri: Option<String>,
    /// REQUIRED if the client is not authenticating with the authorization server.
    pub client_id: Option<String>,
    /// PKCE code verifier per RFC 7636.
    pub code_verifier: Option<String>,
    /// The scope of the access request (OPTIONAL per RFC 6749 §4.1.3).
    pub scope: Option<String>,
    /// Authorization details per RFC 9396 for fine-grained credential requests.
    pub authorization_details: Option<String>,
}

/// Pre-Authorized Code token request per OpenID4VCI §6.1.
///
/// Required: `pre-authorized_code`
/// Conditional: `tx_code` (MUST be present if tx_code was in credential offer)
/// Optional: `client_id`, `scope`, `authorization_details` (RFC 9396)
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAuthorizedCodeRequest {
    /// The code representing the authorization to obtain Credentials (REQUIRED).
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Transaction code; MUST be present if tx_code object was in the Credential Offer.
    pub tx_code: Option<String>,
    /// Only needed when a form of Client Authentication that relies on this parameter is used.
    pub client_id: Option<String>,
    /// The scope of the access request (OPTIONAL).
    pub scope: Option<String>,
    /// Authorization details per RFC 9396 for requesting specific credential configurations.
    pub authorization_details: Option<String>,
}

/// Refresh Token request per RFC 6749 §6.
///
/// Required: `refresh_token`
/// Optional: `scope`, `client_id` (if client not authenticating)
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    /// The refresh token issued to the client (REQUIRED).
    pub refresh_token: String,
    /// The scope of the access request (OPTIONAL per RFC 6749 §6).
    pub scope: Option<String>,
    /// REQUIRED if the client is not authenticating with the authorization server.
    pub client_id: Option<String>,
    /// Authorization details per RFC 9396.
    pub authorization_details: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_authorization_code_request_example() {
        let request = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            redirect_uri: Some("https://wallet.example.org/cb".to_string()),
            client_id: None,
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
            scope: None,
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
            tx_code: Some("493536".to_string()),
            client_id: None,
            scope: None,
            authorization_details: Some(
                r#"[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]"#
                    .to_string(),
            ),
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
            tx_code: None,
            client_id: None,
            scope: None,
            authorization_details: None,
        });

        let json_str = serde_json::to_string(&request).expect("serialize failed");
        assert!(json_str.contains(r#""pre-authorized_code":"abc""#));
    }

    #[test]
    fn refresh_token_request_roundtrip() {
        let request = TokenRequest::RefreshToken(RefreshTokenRequest {
            refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA".to_string(),
            scope: None,
            client_id: Some("wallet_client".to_string()),
            authorization_details: None,
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
