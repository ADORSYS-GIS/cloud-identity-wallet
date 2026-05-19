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
