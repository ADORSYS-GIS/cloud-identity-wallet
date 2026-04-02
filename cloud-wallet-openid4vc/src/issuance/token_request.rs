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
}
