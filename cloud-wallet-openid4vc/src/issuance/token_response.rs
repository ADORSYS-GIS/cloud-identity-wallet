//! Token Response models.
//!
//! Spec references:
//! - OpenID4VCI §6.2: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response>
//! - OpenID4VCI §6.3: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-error-response>
//! - RFC 6749 §5.1: <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// OAuth 2.0 access token type.
///
/// Per RFC 6749 §5.1, token_type values are case-insensitive.
/// This enum supports the known types (Bearer, DPoP) and captures unknown
/// types for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TokenType {
    Bearer,
    DPoP,
    /// Unknown token type returned by the authorization server.
    /// Stored in canonical form (lowercase) for consistent comparison.
    Other(String),
}

impl TryFrom<String> for TokenType {
    type Error = std::convert::Infallible;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "bearer" => Ok(TokenType::Bearer),
            "dpop" => Ok(TokenType::DPoP),
            _ => Ok(TokenType::Other(value)),
        }
    }
}

impl From<TokenType> for String {
    fn from(value: TokenType) -> Self {
        match value {
            TokenType::Bearer => "Bearer".to_string(),
            TokenType::DPoP => "DPoP".to_string(),
            TokenType::Other(s) => s,
        }
    }
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::Bearer => write!(f, "Bearer"),
            TokenType::DPoP => write!(f, "DPoP"),
            TokenType::Other(s) => write!(f, "{s}"),
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

/// A successful Token Response (HTTP 200 OK) per OpenID4VCI §6.2 and RFC 6749 §5.1.
///
/// Required: `access_token`, `token_type`
/// Optional: `expires_in`, `refresh_token`, `scope`, `authorization_details`
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub authorization_details: Option<Vec<TokenResponseAuthorizationDetail>>,
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
        // Unknown types preserve original value
        assert_eq!(
            serde_json::to_value(TokenType::Other("CustomAuth".to_string())).unwrap(),
            json!("CustomAuth")
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
    fn token_type_case_insensitive_deserialization() {
        // RFC 6749 §5.1: token_type value is case-insensitive
        let cases = [
            ("bearer", TokenType::Bearer),
            ("BEARER", TokenType::Bearer),
            ("BeArEr", TokenType::Bearer),
            ("dpop", TokenType::DPoP),
            ("DPOP", TokenType::DPoP),
            ("DpOp", TokenType::DPoP),
        ];

        for (input, expected) in cases {
            let t: TokenType = serde_json::from_str(&format!("\"{input}\"")).unwrap();
            assert_eq!(t, expected, "failed for input: {input}");
        }
    }

    #[test]
    fn token_type_unknown_preserved() {
        // Unknown token types should be captured, not rejected
        let t: TokenType = serde_json::from_str(r#""FutureAuth""#).unwrap();
        assert_eq!(t, TokenType::Other("FutureAuth".to_string()));

        // Round-trip unknown types
        let json = serde_json::to_string(&t).unwrap();
        let roundtripped: TokenType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, roundtripped);
    }

    #[test]
    fn token_type_display() {
        assert_eq!(TokenType::Bearer.to_string(), "Bearer");
        assert_eq!(TokenType::DPoP.to_string(), "DPoP");
        assert_eq!(
            TokenType::Other("CustomAuth".to_string()).to_string(),
            "CustomAuth"
        );
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
    fn spec_successful_bearer_response() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
            "token_type": "Bearer",
            "expires_in": 86400
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");

        assert_eq!(resp.access_token, "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ");
        assert_eq!(resp.token_type, TokenType::Bearer);
        assert_eq!(resp.expires_in, Some(86400));
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
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("expires_in").is_none());
        assert!(json.get("refresh_token").is_none());
    }
}
