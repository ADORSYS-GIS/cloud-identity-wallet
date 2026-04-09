//! OAuth 2.0 token endpoint response types.

use crate::errors::{Error, ErrorKind};
use crate::http::JsonResponse;

/// OAuth 2.0 token endpoint response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    pub access_token: Option<String>,
    /// The type of the token (e.g., "Bearer").
    pub token_type: Option<String>,
    /// The lifetime of the access token in seconds.
    pub expires_in: Option<u64>,
    /// The refresh token for obtaining new access tokens.
    pub refresh_token: Option<String>,
    /// The scope of the access token.
    pub scope: Option<String>,
    /// OpenID4VCI-specific nonce for credential requests.
    pub c_nonce: Option<String>,
    /// Expiration time of the c_nonce in seconds.
    pub c_nonce_expires_in: Option<u64>,
    /// Raw response body.
    pub raw: Option<String>,
}

impl TokenResponse {
    /// Returns the access token, returning an error if not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the access token is not present.
    pub fn require_access_token(&self) -> Result<&str, Error> {
        self.access_token.as_deref().ok_or_else(|| {
            Error::message(
                ErrorKind::HttpResponseParsingFailed,
                "access_token is required",
            )
        })
    }

    /// Returns the c_nonce, returning an error if not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the c_nonce is not present.
    pub fn require_c_nonce(&self) -> Result<&str, Error> {
        self.c_nonce.as_deref().ok_or_else(|| {
            Error::message(ErrorKind::HttpResponseParsingFailed, "c_nonce is required")
        })
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
        .map(String::from);
    let token_type = body
        .get("token_type")
        .and_then(|v| v.as_str())
        .map(String::from);
    let expires_in = body.get("expires_in").and_then(|v| v.as_u64());
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let scope = body.get("scope").and_then(|v| v.as_str()).map(String::from);
    let c_nonce = body
        .get("c_nonce")
        .and_then(|v| v.as_str())
        .map(String::from);
    let c_nonce_expires_in = body.get("c_nonce_expires_in").and_then(|v| v.as_u64());

    Ok(TokenResponse {
        access_token,
        token_type,
        expires_in,
        refresh_token,
        scope,
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
        assert_eq!(token.access_token, Some("abc123".to_string()));
        assert_eq!(token.token_type, Some("Bearer".to_string()));
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(token.refresh_token, Some("refresh123".to_string()));
        assert_eq!(token.scope, Some("openid".to_string()));
        assert_eq!(token.c_nonce, Some("nonce123".to_string()));
        assert_eq!(token.c_nonce_expires_in, Some(300));
    }

    #[test]
    fn token_response_require_methods() {
        let token = TokenResponse {
            access_token: Some("abc123".to_string()),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            c_nonce: Some("nonce123".to_string()),
            c_nonce_expires_in: Some(300),
            raw: None,
        };

        assert!(token.require_access_token().is_ok());
        assert!(token.require_c_nonce().is_ok());

        let token_no_access = TokenResponse {
            access_token: None,
            token_type: Some("Bearer".to_string()),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            c_nonce: Some("nonce123".to_string()),
            c_nonce_expires_in: Some(300),
            raw: None,
        };

        assert!(token_no_access.require_access_token().is_err());
    }
}
