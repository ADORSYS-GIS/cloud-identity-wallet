//! HTTP response types and parsing utilities.

use reqwest::header::HeaderMap;
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::errors::{Error, ErrorKind};

/// Trait for HTTP responses.
pub trait Response {
    /// Returns the HTTP status code.
    fn status(&self) -> StatusCode;

    /// Returns the response headers.
    fn headers(&self) -> &HeaderMap;

    /// Returns the final URL after any redirects.
    fn final_url(&self) -> &Url;

    /// Returns true if the response was successful (2xx).
    fn is_success(&self) -> bool {
        self.status().is_success()
    }
}

/// Raw HTTP response with status, headers, and body.
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body as string (if available).
    pub body: Option<String>,
    /// Final URL after any redirects.
    pub final_url: Url,
}

impl Response for RawResponse {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn final_url(&self) -> &Url {
        &self.final_url
    }
}

impl RawResponse {
    /// Parses the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid JSON or doesn't match the type.
    pub fn parse_json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        let body = self.body.as_ref().ok_or_else(|| {
            Error::message(
                ErrorKind::HttpResponseParsingFailed,
                "response body is empty",
            )
        })?;

        serde_json::from_str(body).map_err(|e| {
            Error::message(
                ErrorKind::HttpResponseParsingFailed,
                format!("failed to parse JSON: {e}"),
            )
        })
    }

    /// Returns the body as bytes.
    #[must_use]
    pub fn body_bytes(&self) -> Option<&[u8]> {
        self.body.as_ref().map(|s| s.as_bytes())
    }

    /// Returns the Content-Type header value.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }

    /// Validates that the response has a specific content type.
    ///
    /// # Errors
    ///
    /// Returns an error if the content type doesn't match.
    pub fn validate_content_type(&self, expected: &str) -> Result<(), Error> {
        let content_type = self.content_type().unwrap_or("");
        let media_type = content_type.split(';').next().unwrap_or("").trim();

        if media_type != expected {
            return Err(Error::message(
                ErrorKind::HttpResponseParsingFailed,
                format!("expected content type '{}', got '{}'", expected, media_type),
            ));
        }

        Ok(())
    }
}

/// JSON response with parsed body.
#[derive(Debug, Clone)]
pub struct JsonResponse<T> {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Parsed JSON body.
    pub body: T,
    /// Raw response body (if available).
    pub raw: Option<String>,
    /// Final URL after any redirects.
    pub final_url: Url,
}

impl<T> Response for JsonResponse<T> {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn final_url(&self) -> &Url {
        &self.final_url
    }
}

impl<T: Clone> JsonResponse<T> {
    /// Returns the raw response body.
    #[must_use]
    pub fn raw_body(&self) -> Option<&str> {
        self.raw.as_deref()
    }

    /// Parses the raw body as a different JSON type.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw body is not available or parsing fails.
    pub fn parse_as<U: DeserializeOwned>(&self) -> Result<U, Error> {
        let raw = self.raw.as_ref().ok_or_else(|| {
            Error::message(
                ErrorKind::HttpResponseParsingFailed,
                "raw body not available",
            )
        })?;

        serde_json::from_str(raw).map_err(|e| {
            Error::message(
                ErrorKind::HttpResponseParsingFailed,
                format!("failed to parse JSON: {e}"),
            )
        })
    }
}

/// Response parser for common OpenID4VCI response types.
pub struct ResponseParser;

impl ResponseParser {
    /// Parses a token endpoint response.
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
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn raw_response_parse_json_success() {
        let response = RawResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: Some(r#"{"key":"value"}"#.to_string()),
            final_url: make_test_url(),
        };

        let parsed: serde_json::Value = response.parse_json().unwrap();
        assert_eq!(parsed["key"], "value");
    }

    #[test]
    fn raw_response_parse_json_empty_body() {
        let response = RawResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: None,
            final_url: make_test_url(),
        };

        let result: Result<serde_json::Value, _> = response.parse_json();
        assert!(result.is_err());
    }

    #[test]
    fn raw_response_validate_content_type() {
        let response = RawResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: None,
            final_url: make_test_url(),
        };

        assert!(response.validate_content_type("application/json").is_ok());
        assert!(response.validate_content_type("text/html").is_err());
    }

    #[test]
    fn json_response_raw_body() {
        let response = JsonResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: serde_json::json!({"key": "value"}),
            raw: Some(r#"{"key":"value"}"#.to_string()),
            final_url: make_test_url(),
        };

        assert_eq!(response.raw_body(), Some(r#"{"key":"value"}"#));
    }

    #[test]
    fn json_response_parse_as_different_type() {
        #[derive(Debug, serde::Deserialize)]
        struct MyData {
            key: String,
        }

        let response = JsonResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: serde_json::json!({"key": "value"}),
            raw: Some(r#"{"key":"value"}"#.to_string()),
            final_url: make_test_url(),
        };

        let parsed: MyData = response.parse_as().unwrap();
        assert_eq!(parsed.key, "value");
    }

    #[test]
    fn response_parser_token_response() {
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

        let token = ResponseParser::parse_token_response(response).unwrap();
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

    #[test]
    fn response_trait_implementation() {
        let raw = RawResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: None,
            final_url: make_test_url(),
        };

        assert!(raw.is_success());
        assert_eq!(raw.status(), StatusCode::OK);

        let json = JsonResponse {
            status: StatusCode::OK,
            headers: make_test_headers(),
            body: serde_json::json!({}),
            raw: None,
            final_url: make_test_url(),
        };

        assert!(json.is_success());
        assert_eq!(json.status(), StatusCode::OK);
    }
}
