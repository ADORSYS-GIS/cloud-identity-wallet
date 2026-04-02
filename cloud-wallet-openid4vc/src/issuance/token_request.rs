//! Token Request models (OID4VCI §6.1 / RFC 6749 §4.1.3).

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};

/// Token Request as defined in [OID4VCI §6.1] and [RFC 6749 §4.1.3].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "grant_type")]
pub enum TokenRequest {
    #[serde(rename = "authorization_code")]
    AuthorizationCode(AuthorizationCodeRequest),

    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(PreAuthorizedCodeRequest),

    #[serde(rename = "refresh_token")]
    RefreshToken(RefreshTokenRequest),
}

/// Standard authorization code grant (`authorization_code`).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub authorization_details: Option<String>,
}

/// OID4VCI Pre-Authorized Code grant.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreAuthorizedCodeRequest {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    pub tx_code: Option<String>,
    pub client_id: Option<String>,
    pub authorization_details: Option<String>,
}

/// Standard refresh token grant (`refresh_token`).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub client_id: Option<String>,
    pub authorization_details: Option<String>,
}

impl TokenRequest {
    /// Validates the request (e.g. checks for blank mandatory fields).
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            TokenRequest::AuthorizationCode(req) => {
                if req.code.trim().is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidTokenRequest,
                        "authorization_code grant requires a non-empty 'code' parameter",
                    ));
                }
            }
            TokenRequest::PreAuthorizedCode(req) => {
                if req.pre_authorized_code.trim().is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidTokenRequest,
                        "pre_authorized_code grant requires a non-empty 'pre-authorized_code' parameter",
                    ));
                }
            }
            TokenRequest::RefreshToken(req) => {
                if req.refresh_token.trim().is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidTokenRequest,
                        "refresh_token grant requires a non-empty 'refresh_token' parameter",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Serializes the request as `application/x-www-form-urlencoded` key-value pairs.
    ///
    /// Required by [RFC 6749 §4.1.3] which mandates form-encoded bodies for all
    /// Token Endpoint requests.  The returned pairs can be passed directly to
    /// HTTP client form APIs (e.g. `reqwest::RequestBuilder::form`).
    pub fn to_form(&self) -> Vec<(&'static str, String)> {
        let mut params: Vec<(&'static str, String)> = Vec::new();

        match self {
            TokenRequest::AuthorizationCode(req) => {
                params.push(("grant_type", "authorization_code".to_string()));
                params.push(("code", req.code.clone()));
                if let Some(v) = &req.redirect_uri {
                    params.push(("redirect_uri", v.clone()));
                }
                if let Some(v) = &req.client_id {
                    params.push(("client_id", v.clone()));
                }
                if let Some(v) = &req.code_verifier {
                    params.push(("code_verifier", v.clone()));
                }
                if let Some(v) = &req.authorization_details {
                    params.push(("authorization_details", v.clone()));
                }
            }
            TokenRequest::PreAuthorizedCode(req) => {
                params.push((
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                ));
                params.push(("pre-authorized_code", req.pre_authorized_code.clone()));
                if let Some(v) = &req.tx_code {
                    params.push(("tx_code", v.clone()));
                }
                if let Some(v) = &req.client_id {
                    params.push(("client_id", v.clone()));
                }
                if let Some(v) = &req.authorization_details {
                    params.push(("authorization_details", v.clone()));
                }
            }
            TokenRequest::RefreshToken(req) => {
                params.push(("grant_type", "refresh_token".to_string()));
                params.push(("refresh_token", req.refresh_token.clone()));
                if let Some(v) = &req.client_id {
                    params.push(("client_id", v.clone()));
                }
                if let Some(v) = &req.authorization_details {
                    params.push(("authorization_details", v.clone()));
                }
            }
        }

        params
    }
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
            authorization_details: None,
        });

        assert!(request.validate().is_ok());

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
            authorization_details: Some(
                r#"[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]"#
                    .to_string(),
            ),
        });

        assert!(request.validate().is_ok());

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
            authorization_details: None,
        });

        let json_str = serde_json::to_string(&request).expect("serialize failed");
        assert!(json_str.contains(r#""pre-authorized_code":"abc""#));
    }

    #[test]
    fn refresh_token_request_roundtrip() {
        let request = TokenRequest::RefreshToken(RefreshTokenRequest {
            refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA".to_string(),
            client_id: Some("wallet_client".to_string()),
            authorization_details: None,
        });

        assert!(request.validate().is_ok());

        let json = serde_json::to_string(&request).expect("serialize failed");
        let roundtripped: TokenRequest = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(request, roundtripped);
    }

    #[test]
    fn validation_auth_code_blank_code() {
        let request = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: "   ".to_string(),
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            authorization_details: None,
        });

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenRequest);
    }

    #[test]
    fn validation_pre_auth_blank_code() {
        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "   ".to_string(),
            tx_code: None,
            client_id: None,
            authorization_details: None,
        });

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenRequest);
    }

    #[test]
    fn validation_refresh_token_blank_token() {
        let request = TokenRequest::RefreshToken(RefreshTokenRequest {
            refresh_token: "   ".to_string(),
            client_id: None,
            authorization_details: None,
        });

        let err = request.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenRequest);
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


    fn form_map(
        pairs: Vec<(&'static str, String)>,
    ) -> std::collections::HashMap<&'static str, String> {
        pairs.into_iter().collect()
    }

    #[test]
    fn to_form_authorization_code() {
        let req = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: "abc123".to_string(),
            redirect_uri: Some("https://wallet.example.org/cb".to_string()),
            client_id: None,
            code_verifier: Some("verifier".to_string()),
            authorization_details: None,
        });

        let form = form_map(req.to_form());

        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "abc123");
        assert_eq!(form["redirect_uri"], "https://wallet.example.org/cb");
        assert_eq!(form["code_verifier"], "verifier");
        assert!(!form.contains_key("client_id"));
        assert!(!form.contains_key("authorization_details"));
    }

    #[test]
    fn to_form_pre_authorized_code() {
        let req = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
            tx_code: Some("493536".to_string()),
            client_id: None,
            authorization_details: None,
        });

        let form = form_map(req.to_form());

        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        );
        assert_eq!(form["pre-authorized_code"], "SplxlOBeZQQYbYS6WxSbIA");
        assert_eq!(form["tx_code"], "493536");
        assert!(!form.contains_key("client_id"));
    }

    #[test]
    fn to_form_refresh_token() {
        let req = TokenRequest::RefreshToken(RefreshTokenRequest {
            refresh_token: "tGzv3JOkF0XG5Qx2TlKWIA".to_string(),
            client_id: Some("wallet_client".to_string()),
            authorization_details: None,
        });

        let form = form_map(req.to_form());

        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], "tGzv3JOkF0XG5Qx2TlKWIA");
        assert_eq!(form["client_id"], "wallet_client");
    }

    #[test]
    fn to_form_omits_none_fields() {
        let req = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: "code".to_string(),
            redirect_uri: None,
            client_id: None,
            code_verifier: None,
            authorization_details: None,
        });

        let form = form_map(req.to_form());

        assert!(!form.contains_key("redirect_uri"));
        assert!(!form.contains_key("client_id"));
        assert!(!form.contains_key("code_verifier"));
    }
}
