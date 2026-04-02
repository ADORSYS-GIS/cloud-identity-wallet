//! Token Response models (OID4VCI §6.2, §6.3, and RFC 6749 §5).

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};

/// OAuth 2.0 access token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Bearer,
    DPoP,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::Bearer => write!(f, "Bearer"),
            TokenType::DPoP => write!(f, "DPoP"),
        }
    }
}

/// An `authorization_details` entry returned in a successful Token Response.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponseAuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,

    pub credential_configuration_id: Option<String>,

    pub locations: Option<Vec<String>>,

    /// Identifiers for the credentials being issued.
    pub credential_identifiers: Vec<String>,
}

impl TokenResponseAuthorizationDetail {
    pub fn validate(&self) -> Result<(), Error> {
        if self.detail_type != "openid_credential" {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                format!(
                    "authorization_details type must be 'openid_credential', got '{}'",
                    self.detail_type
                ),
            ));
        }
        if self.credential_identifiers.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                "authorization_details.credential_identifiers must not be empty",
            ));
        }
        Ok(())
    }
}

/// A successful Token Response (HTTP 200 OK).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,

    pub expires_in: Option<u64>,

    pub refresh_token: Option<String>,

    pub scope: Option<String>,

    pub authorization_details: Option<Vec<TokenResponseAuthorizationDetail>>,

    /// OID4VCI extension: nonce for subsequent requests.
    pub c_nonce: Option<String>,

    pub c_nonce_expires_in: Option<u64>,
}

impl TokenResponse {
    pub fn validate(&self) -> Result<(), Error> {
        if self.access_token.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidTokenResponse,
                "access_token must not be empty",
            ));
        }
        if let Some(ref details) = self.authorization_details {
            for detail in details {
                detail.validate()?;
            }
        }
        Ok(())
    }
}

/// Normative error codes for the Token Error Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenErrorCode {
    InvalidRequest,

    InvalidClient,

    InvalidGrant,

    UnauthorizedClient,

    UnsupportedGrantType,

    InvalidScope,
}

impl std::fmt::Display for TokenErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// A Token Error Response (HTTP 400 Bad Request).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenErrorResponse {
    pub error: TokenErrorCode,

    pub error_description: Option<String>,

    pub error_uri: Option<String>,
}

impl TokenErrorResponse {
    pub fn new(error: TokenErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }
}

impl std::fmt::Display for TokenErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(ref desc) = self.error_description {
            write!(f, ": {desc}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TokenErrorResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_type_wire_values() {
        assert_eq!(
            serde_json::to_value(TokenType::Bearer).unwrap(),
            json!("Bearer")
        );
        assert_eq!(
            serde_json::to_value(TokenType::DPoP).unwrap(),
            json!("DPoP")
        );
    }

    #[test]
    fn token_type_deserialization() {
        let t: TokenType = serde_json::from_str(r#""Bearer""#).unwrap();
        assert_eq!(t, TokenType::Bearer);

        let t: TokenType = serde_json::from_str(r#""DPoP""#).unwrap();
        assert_eq!(t, TokenType::DPoP);
    }

    #[test]
    fn token_type_display() {
        assert_eq!(TokenType::Bearer.to_string(), "Bearer");
        assert_eq!(TokenType::DPoP.to_string(), "DPoP");
    }

    #[test]
    fn token_error_code_wire_values() {
        let cases = [
            (TokenErrorCode::InvalidRequest, "invalid_request"),
            (TokenErrorCode::InvalidClient, "invalid_client"),
            (TokenErrorCode::InvalidGrant, "invalid_grant"),
            (TokenErrorCode::UnauthorizedClient, "unauthorized_client"),
            (
                TokenErrorCode::UnsupportedGrantType,
                "unsupported_grant_type",
            ),
            (TokenErrorCode::InvalidScope, "invalid_scope"),
        ];

        for (code, expected) in cases {
            assert_eq!(serde_json::to_value(code).unwrap(), json!(expected));
        }
    }

    #[test]
    fn token_error_code_display() {
        assert_eq!(
            TokenErrorCode::InvalidRequest.to_string(),
            "invalid_request"
        );
        assert_eq!(TokenErrorCode::InvalidGrant.to_string(), "invalid_grant");
    }

    #[test]
    fn spec_error_response_invalid_request() {
        let json = r#"{"error": "invalid_request"}"#;
        let resp: TokenErrorResponse = serde_json::from_str(json).expect("deser failed");
        assert_eq!(resp.error, TokenErrorCode::InvalidRequest);
    }

    #[test]
    fn deserialize_error_response_invalid_grant() {
        let json = r#"{"error": "invalid_grant"}"#;
        let resp: TokenErrorResponse = serde_json::from_str(json).expect("deser failed");
        assert_eq!(resp.error, TokenErrorCode::InvalidGrant);
    }

    #[test]
    fn serialize_error_response_with_description() {
        let resp = TokenErrorResponse::new(TokenErrorCode::InvalidGrant)
            .with_description("Pre-authorized code has expired");

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"], "invalid_grant");
        assert_eq!(json["error_description"], "Pre-authorized code has expired");
    }

    #[test]
    fn error_response_display() {
        let resp = TokenErrorResponse::new(TokenErrorCode::InvalidClient)
            .with_description("Anonymous access is not supported");

        assert_eq!(
            resp.to_string(),
            "invalid_client: Anonymous access is not supported"
        );
    }

    #[test]
    fn auth_detail_rejects_wrong_type() {
        let detail = TokenResponseAuthorizationDetail {
            detail_type: "unknown_type".to_string(),
            credential_configuration_id: None,
            locations: None,
            credential_identifiers: vec!["id1".to_string()],
        };

        let err = detail.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
    }

    #[test]
    fn auth_detail_rejects_empty_credential_identifiers() {
        let detail = TokenResponseAuthorizationDetail {
            detail_type: "openid_credential".to_string(),
            credential_configuration_id: Some("UniversityDegreeCredential".to_string()),
            locations: None,
            credential_identifiers: vec![],
        };

        let err = detail.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidTokenResponse);
    }

    #[test]
    fn spec_successful_bearer_response_with_c_nonce() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
            "token_type": "Bearer",
            "expires_in": 86400,
            "c_nonce": "tZignsnFbp",
            "c_nonce_expires_in": 86400
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");

        assert_eq!(resp.access_token, "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ");
        assert_eq!(resp.token_type, TokenType::Bearer);
        assert_eq!(resp.expires_in, Some(86400));
        assert_eq!(resp.c_nonce.as_deref(), Some("tZignsnFbp"));
        assert_eq!(resp.c_nonce_expires_in, Some(86400));
        assert!(resp.validate().is_ok());
    }

    #[test]
    fn spec_rar_response_with_credential_identifiers() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
            "token_type": "Bearer",
            "expires_in": 86400,
            "authorization_details": [
                {
                    "type": "openid_credential",
                    "credential_configuration_id": "UniversityDegreeCredential",
                    "credential_identifiers": [
                        "CivilEngineeringDegree-2023",
                        "ElectricalEngineeringDegree-2023"
                    ]
                }
            ]
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");
        assert!(resp.validate().is_ok());

        let details = resp.authorization_details.as_ref().unwrap();
        assert_eq!(details.len(), 1);

        let detail = &details[0];
        assert_eq!(detail.detail_type, "openid_credential");
        assert_eq!(detail.credential_identifiers.len(), 2);
    }

    #[test]
    fn spec_dpop_response() {
        let json = r#"{
            "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            "token_type": "DPoP",
            "expires_in": 3600
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");
        assert_eq!(resp.token_type, TokenType::DPoP);
        assert!(resp.validate().is_ok());
    }

    #[test]
    fn validation_rejects_blank_access_token() {
        let resp = TokenResponse {
            access_token: "   ".to_string(),
            token_type: TokenType::Bearer,
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
            c_nonce: None,
            c_nonce_expires_in: None,
        };

        assert!(resp.validate().is_err());
    }

    #[test]
    fn token_response_roundtrip() {
        let resp = TokenResponse {
            access_token: "my-access-token".to_string(),
            token_type: TokenType::Bearer,
            expires_in: Some(3600),
            refresh_token: Some("my-refresh-token".to_string()),
            scope: None,
            authorization_details: Some(vec![TokenResponseAuthorizationDetail {
                detail_type: "openid_credential".to_string(),
                credential_configuration_id: Some("MyCredential".to_string()),
                locations: None,
                credential_identifiers: vec!["cred-001".to_string()],
            }]),
            c_nonce: Some("abc123".to_string()),
            c_nonce_expires_in: Some(300),
        };

        let json = serde_json::to_string(&resp).expect("serialize failed");
        let roundtripped: TokenResponse = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(resp, roundtripped);
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let resp = TokenResponse {
            access_token: "token".to_string(),
            token_type: TokenType::Bearer,
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
            c_nonce: None,
            c_nonce_expires_in: None,
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("expires_in").is_none());
        assert!(json.get("refresh_token").is_none());
        assert!(json.get("c_nonce").is_none());
    }
}
