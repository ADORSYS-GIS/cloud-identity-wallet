//! Token Response models.
//!
//! Spec references:
//! - OpenID4VCI §6.2: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response>
//! - RFC 6749 §5.1: <https://www.rfc-editor.org/rfc/rfc6749#section-5.1>

use crate::errors::{Error, ErrorKind};
use crate::http::JsonResponse;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::authz_details::AuthorizationDetails;

/// A successful Token Response (HTTP 200 OK) per OpenID4VCI §6.2 and RFC 6749 §5.1.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Authorization details returned by the AS, including credential identifiers.
    pub authorization_details: Option<Vec<AuthorizationDetails>>,
    /// OpenID4VCI-specific nonce for credential requests.
    pub c_nonce: Option<String>,
    /// Expiration time of the c_nonce in seconds.
    pub c_nonce_expires_in: Option<u64>,
    /// Raw response body captured by the HTTP utility layer.
    #[serde(skip)]
    pub raw: Option<String>,
}

impl TokenResponse {
    /// Returns the access token.
    #[must_use]
    pub fn require_access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the c_nonce, returning an error if not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the c_nonce is not present.
    pub fn require_c_nonce(&self) -> Result<&str, Error> {
        self.c_nonce
            .as_deref()
            .ok_or_else(|| Error::message(ErrorKind::InvalidTokenResponse, "c_nonce is required"))
    }
}

/// Parses a token endpoint response from JSON.
///
/// # Errors
///
/// Returns an error if the response is not a valid token response.
pub fn parse_token_response(
    response: JsonResponse<serde_json::Value>,
) -> Result<TokenResponse, Error> {
    let body = response.body;

    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::message(ErrorKind::InvalidTokenResponse, "access_token is required"))?
        .to_owned();
    let token_type = body
        .get("token_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::message(ErrorKind::InvalidTokenResponse, "token_type is required"))?
        .to_owned();
    let expires_in = body.get("expires_in").and_then(|v| v.as_u64());
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let scope = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let authorization_details = body
        .get("authorization_details")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| Error::message(ErrorKind::InvalidTokenResponse, e.to_string()))?;
    let c_nonce = body
        .get("c_nonce")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let c_nonce_expires_in = body.get("c_nonce_expires_in").and_then(|v| v.as_u64());

    Ok(TokenResponse {
        access_token,
        token_type,
        expires_in,
        refresh_token,
        scope,
        authorization_details,
        c_nonce,
        c_nonce_expires_in,
        raw: response.raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response::JsonResponse;
    use reqwest::StatusCode;
    use reqwest::header::HeaderMap;
    use url::Url;

    fn make_test_url() -> Url {
        Url::parse("https://example.com").unwrap()
    }

    fn make_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers
    }

    #[test]
    fn parse_token_response_success() {
        let response = JsonResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: serde_json::json!({
                "access_token": "abc123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh123",
                "scope": "openid",
                "c_nonce": "nonce123",
                "c_nonce_expires_in": 300
            }),
            raw: None,
            final_url: make_test_url(),
        };

        let token = parse_token_response(response).unwrap();
        assert_eq!(token.access_token, "abc123");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(token.refresh_token.as_deref(), Some("refresh123"));
        assert_eq!(token.scope.as_deref(), Some("openid"));
        assert_eq!(token.c_nonce.as_deref(), Some("nonce123"));
        assert_eq!(token.c_nonce_expires_in, Some(300));
        assert!(token.authorization_details.is_none());
    }

    #[test]
    fn token_response_require_methods() {
        let token = TokenResponse {
            access_token: "abc123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            authorization_details: None,
            c_nonce: Some("nonce123".to_string()),
            c_nonce_expires_in: Some(300),
            raw: None,
        };

        assert_eq!(token.require_access_token(), "abc123");
        assert!(token.require_c_nonce().is_ok());

        let token_no_nonce = TokenResponse {
            access_token: "abc123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            authorization_details: None,
            c_nonce: None,
            c_nonce_expires_in: Some(300),
            raw: None,
        };

        assert!(token_no_nonce.require_c_nonce().is_err());
    }

    #[test]
    fn parse_token_response_with_authorization_details() {
        use crate::issuance::authz_details::AuthorizationDetailType;

        let response = JsonResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: serde_json::json!({
                "access_token": "abc123",
                "token_type": "Bearer",
                "authorization_details": [
                    {
                        "type": "openid_credential",
                        "credential_configuration_id": "UniversityDegreeCredential",
                        "credential_identifiers": ["cred-001"]
                    }
                ]
            }),
            raw: Some("{\"access_token\":\"abc123\"}".to_string()),
            final_url: make_test_url(),
        };

        let token = parse_token_response(response).unwrap();
        let details = token.authorization_details.unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].r#type, AuthorizationDetailType::OpenidCredential);
        assert_eq!(
            details[0].credential_identifiers.as_deref(),
            Some(&["cred-001".to_string()][..])
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
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, Some(86400));
    }

    #[test]
    fn spec_rar_response_with_credential_identifiers() {
        use crate::issuance::authz_details::AuthorizationDetailType;

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
        assert_eq!(detail.r#type, AuthorizationDetailType::OpenidCredential);
        assert_eq!(detail.credential_identifiers.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn spec_dpop_response() {
        let json = r#"{
            "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
            "token_type": "DPoP",
            "expires_in": 3600
        }"#;

        let resp: TokenResponse = serde_json::from_str(json).expect("deser failed");
        assert_eq!(resp.token_type, "DPoP");
    }

    #[test]
    fn token_response_roundtrip() {
        use crate::issuance::authz_details::AuthorizationDetailType;

        let resp = TokenResponse {
            access_token: "my-access-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: Some("my-refresh-token".to_string()),
            scope: None,
            authorization_details: Some(vec![AuthorizationDetails {
                r#type: AuthorizationDetailType::OpenidCredential,
                credential_configuration_id: "MyCredential".to_string(),
                locations: None,
                claims: None,
                credential_identifiers: Some(vec!["cred-001".to_string()]),
            }]),
            c_nonce: Some("nonce-123".to_string()),
            c_nonce_expires_in: Some(60),
            raw: Some("raw-json".to_string()),
        };

        let json = serde_json::to_string(&resp).expect("serialize failed");
        let roundtripped: TokenResponse = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(roundtripped.access_token, resp.access_token);
        assert_eq!(roundtripped.token_type, resp.token_type);
        assert_eq!(roundtripped.expires_in, resp.expires_in);
        assert_eq!(roundtripped.refresh_token, resp.refresh_token);
        assert_eq!(roundtripped.scope, resp.scope);
        assert_eq!(
            roundtripped.authorization_details,
            resp.authorization_details
        );
        assert_eq!(roundtripped.c_nonce, resp.c_nonce);
        assert_eq!(roundtripped.c_nonce_expires_in, resp.c_nonce_expires_in);
        assert!(roundtripped.raw.is_none());
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let resp = TokenResponse {
            access_token: "token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
            c_nonce: None,
            c_nonce_expires_in: None,
            raw: None,
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("expires_in").is_none());
        assert!(json.get("refresh_token").is_none());
        assert!(json.get("c_nonce").is_none());
        assert!(json.get("c_nonce_expires_in").is_none());
        assert!(json.get("raw").is_none());
    }
}
