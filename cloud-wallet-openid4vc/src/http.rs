//! HTTP client utilities for OpenID4VCI wallet components.
//!
//! This module provides reusable HTTP client utilities for interacting with
//! issuer and authorization server endpoints during the credential issuance
//! process. The utilities provide a consistent interface for performing HTTP
//! requests and handling responses with security best practices built-in.
//!
//! # Security Considerations
//!
//! The client builder enforces security defaults:
//! - HTTPS-only connections (configurable for testing)
//! - Redirect restrictions to prevent SSRF attacks
//! - Configurable timeouts to prevent hanging
//! - Response size limits to prevent memory exhaustion
//!
//! # Example
//!
//! ```ignore
//! use cloud_wallet_openid4vc::http::{HttpClientBuilder, JsonResponse};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = HttpClientBuilder::new().build()?;
//!     let response: JsonResponse<serde_json::Value> = client
//!         .get_json("https://issuer.example.com/metadata")
//!         .send()
//!         .await?;
//!     println!("Response: {:?}", response.body);
//!     Ok(())
//! }
//! ```

use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

use crate::errors::{Error, ErrorKind};

pub mod client;
pub mod request;
pub mod response;

pub use client::{HttpClient, HttpClientBuilder};
pub use request::{FormRequestBuilder, JsonRequestBuilder, RequestBuilder};
pub use response::{JsonResponse, RawResponse, Response};

/// Default connection timeout in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default request timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum response size in bytes (1 MB).
const DEFAULT_MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Authorization header types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthHeader {
    /// Bearer token authorization.
    Bearer(String),
    /// Basic authorization (base64-encoded credentials).
    Basic(String),
    /// DPoP-bound bearer token.
    Dpop { token: String, proof: String },
}

impl AuthHeader {
    /// Creates a Bearer authorization header.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(token.into())
    }

    /// Creates a Basic authorization header from username and password.
    #[must_use]
    pub fn basic(username: &str, password: &str) -> Self {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        Self::Basic(encoded)
    }

    /// Creates a DPoP-bound authorization header.
    #[must_use]
    pub fn dpop(token: impl Into<String>, proof: impl Into<String>) -> Self {
        Self::Dpop {
            token: token.into(),
            proof: proof.into(),
        }
    }

    /// Converts the authorization header to a `HeaderValue`.
    ///
    /// # Errors
    ///
    /// Returns an error if the header value contains invalid characters.
    pub fn to_header_value(&self) -> Result<HeaderValue, Error> {
        let value = match self {
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::Basic(encoded) => format!("Basic {encoded}"),
            Self::Dpop { token, .. } => format!("DPoP {token}"),
        };
        HeaderValue::try_from(value).map_err(|e| {
            Error::message(ErrorKind::HttpRequestFailed, format!("invalid authorization header: {e}"))
        })
    }

    /// Returns additional headers needed for this authorization type.
    pub fn additional_headers(&self) -> Option<HeaderMap> {
        match self {
            Self::Dpop { proof, .. } => {
                let mut headers = HeaderMap::new();
                headers.insert("DPoP", HeaderValue::from_str(proof).ok()?);
                Some(headers)
            }
            _ => None,
        }
    }
}

/// An HTTP error response with status code and optional body.
#[derive(Debug, Clone)]
pub struct HttpError {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response body (if available).
    pub body: Option<String>,
    /// Response headers.
    pub headers: HeaderMap,
}

impl HttpError {
    /// Creates a new HTTP error from a response.
    #[must_use]
    pub fn new(status: StatusCode, body: Option<String>, headers: HeaderMap) -> Self {
        Self {
            status,
            body,
            headers,
        }
    }

    /// Returns true if this is a client error (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        self.status.is_client_error()
    }

    /// Returns true if this is a server error (5xx).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// Parses the error body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid JSON.
    pub fn parse_body_as_json<T: DeserializeOwned>(&self) -> Result<Option<T>, Error> {
        if let Some(ref body) = self.body {
            let parsed: T = serde_json::from_str(body).map_err(|e| {
                Error::message(
                    ErrorKind::HttpResponseParsingFailed,
                    format!("failed to parse error body as JSON: {e}"),
                )
            })?;
            Ok(Some(parsed))
        } else {
            Ok(None)
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}", self.status)?;
        if let Some(ref body) = self.body
            && !body.is_empty() {
                write!(f, ": {body}")?;
            }
        Ok(())
    }
}

impl std::error::Error for HttpError {}

/// Converts a `reqwest::Error` to our `Error` type.
pub(crate) fn map_reqwest_error(e: reqwest::Error) -> Error {
    if e.is_timeout() {
        Error::message(ErrorKind::HttpRequestFailed, format!("request timed out: {e}"))
    } else if e.is_connect() {
        Error::message(ErrorKind::HttpRequestFailed, format!("connection failed: {e}"))
    } else if e.is_body() || e.is_decode() {
        Error::message(
            ErrorKind::HttpResponseParsingFailed,
            format!("response body error: {e}"),
        )
    } else {
        Error::new(ErrorKind::HttpRequestFailed, e)
    }
}
