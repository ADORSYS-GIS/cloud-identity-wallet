//! HTTP client builder and client implementation.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Method, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{Error, ErrorKind};
use crate::http::request::JsonRequestBuilder;
use crate::http::{
    DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_RESPONSE_SIZE, DEFAULT_TIMEOUT_SECS,
    map_reqwest_error,
};

use super::request::FormRequestBuilder;

/// Builder for creating HTTP clients with security best practices.
///
/// # Security Defaults
///
/// - HTTPS-only connections (configurable for testing)
/// - Redirect restrictions to prevent SSRF attacks
/// - Configurable timeouts to prevent hanging
/// - Response size limits to prevent memory exhaustion
///
/// # Example
///
/// ```no_run
/// use cloud_wallet_openid4vc::http::HttpClientBuilder;
///
/// let client = HttpClientBuilder::new()
///     .timeout(std::time::Duration::from_secs(60))
///     .max_response_size(2 * 1024 * 1024) // 2 MB
///     .build()?;
/// # Ok::<(), cloud_wallet_openid4vc::errors::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct HttpClientBuilder {
    connect_timeout: Duration,
    timeout: Duration,
    max_response_size: usize,
    redirect_policy: RedirectPolicy,
    accept_invalid_certs: bool,
    allow_http_urls: bool,
    user_agent: Option<String>,
    default_headers: HeaderMap,
}

/// Redirect policy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// No redirects allowed.
    None,
    /// Allow redirects but limit the number.
    Limited(usize),
    /// Allow redirects up to a safety limit of 10.
    Default,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_response_size: DEFAULT_MAX_RESPONSE_SIZE,
            redirect_policy: RedirectPolicy::None,
            accept_invalid_certs: false,
            allow_http_urls: false,
            user_agent: None,
            default_headers: HeaderMap::new(),
        }
    }
}

impl HttpClientBuilder {
    /// Creates a new builder with security defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection timeout.
    ///
    /// Defaults to 10 seconds.
    #[must_use]
    pub fn connect_timeout(mut self, duration: Duration) -> Self {
        self.connect_timeout = duration;
        self
    }

    /// Sets the total request timeout.
    ///
    /// Defaults to 30 seconds.
    #[must_use]
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Sets the maximum response size in bytes.
    ///
    /// Defaults to 1 MB (1,048,576 bytes).
    #[must_use]
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.max_response_size = size;
        self
    }

    /// Sets the redirect policy.
    ///
    /// Defaults to [`RedirectPolicy::None`].
    ///
    /// # Security Warning
    ///
    /// Allowing redirects can enable SSRF attacks. Use `RedirectPolicy::None`
    /// for the most secure option, or `RedirectPolicy::Limited` with a low
    /// limit if redirects are necessary.
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Accepts invalid TLS certificates.
    ///
    /// Defaults to `false`.
    ///
    /// # Security Warning
    ///
    /// This should only be used for testing. Never use in production.
    #[must_use]
    pub fn accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }

    /// Allows HTTP URLs (for testing only).
    ///
    /// Defaults to `false`.
    ///
    /// # Security Warning
    ///
    /// This should only be used for testing. Never use in production.
    #[must_use]
    pub fn allow_http_urls(mut self, allow: bool) -> Self {
        self.allow_http_urls = allow;
        self
    }

    /// Sets a custom user agent.
    ///
    /// Defaults to the `reqwest` default user agent.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Adds a default header to all requests.
    #[must_use]
    pub fn default_header(mut self, key: &'static str, value: &str) -> Self {
        if let Ok(header_name) = HeaderName::try_from(key)
            && let Ok(header_value) = HeaderValue::try_from(value)
        {
            self.default_headers.insert(header_name, header_value);
        }
        self
    }

    /// Builds the HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if the client could not be built (e.g., invalid TLS configuration).
    pub fn build(self) -> Result<HttpClient, Error> {
        let redirect_policy = match self.redirect_policy {
            RedirectPolicy::None => Policy::none(),
            RedirectPolicy::Limited(n) => Policy::limited(n),
            RedirectPolicy::Default => Policy::limited(10),
        };

        let mut builder = Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.timeout)
            .redirect(redirect_policy)
            .danger_accept_invalid_certs(self.accept_invalid_certs);

        if let Some(ref user_agent) = self.user_agent {
            builder = builder.user_agent(user_agent);
        }

        builder = builder.default_headers(self.default_headers);

        let client = builder.build().map_err(|e| {
            Error::message(
                ErrorKind::HttpRequestFailed,
                format!("failed to build HTTP client: {e}"),
            )
        })?;

        Ok(HttpClient {
            inner: client,
            max_response_size: self.max_response_size,
            allow_http_urls: self.allow_http_urls,
        })
    }
}

/// HTTP client for making requests to issuer and authorization server endpoints.
///
/// This client provides methods for making JSON and form-encoded requests
/// with built-in error handling and response parsing.
#[derive(Debug, Clone)]
pub struct HttpClient {
    pub(crate) inner: Client,
    pub(crate) max_response_size: usize,
    pub(crate) allow_http_urls: bool,
}

impl HttpClient {
    /// Creates a new client with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the client could not be built.
    pub fn new() -> Result<Self, Error> {
        HttpClientBuilder::new().build()
    }

    /// Returns the maximum response size.
    #[must_use]
    pub fn max_response_size(&self) -> usize {
        self.max_response_size
    }

    /// Creates a GET request for JSON content.
    #[must_use]
    pub fn get_json<T: DeserializeOwned>(&self, url: &str) -> JsonRequestBuilder<'_, T> {
        JsonRequestBuilder::new(self, Method::GET, url)
    }

    /// Creates a POST request with a JSON body.
    #[must_use]
    pub fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        url: &str,
    ) -> JsonRequestBuilder<'_, T, B> {
        JsonRequestBuilder::new(self, Method::POST, url)
    }

    /// Creates a POST request with a form-encoded body.
    #[must_use]
    pub fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
    ) -> FormRequestBuilder<'_, T> {
        FormRequestBuilder::new(self, url)
    }

    /// Creates a request builder for custom requests.
    #[must_use]
    pub fn request(&self, method: Method, url: &str) -> crate::http::request::RequestBuilder<'_> {
        crate::http::request::RequestBuilder::new(self, method, url)
    }

    /// Executes a raw request and returns the response.
    ///
    /// This is a low-level method. Prefer using `get_json`, `post_json`, or `post_form`.
    pub(crate) async fn execute_raw(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, Error> {
        self.inner.execute(request).await.map_err(map_reqwest_error)
    }

    /// Validates that a URL uses HTTPS.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL does not use HTTPS.
    pub fn validate_https_url(&self, url: &str) -> Result<Url, Error> {
        let parsed = Url::parse(url).map_err(|e| {
            Error::message(ErrorKind::HttpRequestFailed, format!("invalid URL: {e}"))
        })?;

        if parsed.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::HttpRequestFailed,
                format!("URL must use https scheme, got '{}'", parsed.scheme()),
            ));
        }

        Ok(parsed)
    }

    /// Validates URL and checks for redirect attacks after response.
    ///
    /// This is used by credential offer resolution to detect SSRF attacks.
    pub fn validate_final_url(&self, original: &Url, final_url: &Url) -> Result<(), Error> {
        if final_url.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::HttpRequestFailed,
                format!(
                    "redirect changed scheme from https to '{}'",
                    final_url.scheme()
                ),
            ));
        }
        if final_url.host() != original.host() {
            return Err(Error::message(
                ErrorKind::HttpRequestFailed,
                format!(
                    "redirect changed host from '{}' to '{}'",
                    original.host().map(|h| h.to_string()).unwrap_or_default(),
                    final_url.host().map(|h| h.to_string()).unwrap_or_default()
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_creates_client_with_defaults() {
        let client = HttpClientBuilder::new().build().unwrap();
        assert_eq!(client.max_response_size(), DEFAULT_MAX_RESPONSE_SIZE);
    }

    #[test]
    fn builder_customizes_timeout() {
        let _client = HttpClientBuilder::new()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
    }

    #[test]
    fn builder_customizes_max_response_size() {
        let client = HttpClientBuilder::new()
            .max_response_size(2 * 1024 * 1024)
            .build()
            .unwrap();
        assert_eq!(client.max_response_size(), 2 * 1024 * 1024);
    }

    #[test]
    fn builder_sets_user_agent() {
        let _client = HttpClientBuilder::new()
            .user_agent("test-agent/1.0")
            .build()
            .unwrap();
    }

    #[test]
    fn validate_https_url_accepts_https() {
        let client = HttpClient::new().unwrap();
        let result = client.validate_https_url("https://example.com/path");
        assert!(result.is_ok());
    }

    #[test]
    fn validate_https_url_rejects_http() {
        let client = HttpClient::new().unwrap();
        let result = client.validate_https_url("http://example.com/path");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::HttpRequestFailed);
    }

    #[test]
    fn validate_https_url_rejects_invalid_url() {
        let client = HttpClient::new().unwrap();
        let result = client.validate_https_url("not a valid url");
        assert!(result.is_err());
    }

    #[test]
    fn validate_final_url_detects_scheme_change() {
        let client = HttpClient::new().unwrap();
        let original = Url::parse("https://example.com").unwrap();
        let final_url = Url::parse("http://evil.com").unwrap();
        let result = client.validate_final_url(&original, &final_url);
        assert!(result.is_err());
    }

    #[test]
    fn validate_final_url_detects_host_change() {
        let client = HttpClient::new().unwrap();
        let original = Url::parse("https://example.com").unwrap();
        let final_url = Url::parse("https://evil.com").unwrap();
        let result = client.validate_final_url(&original, &final_url);
        assert!(result.is_err());
    }

    #[test]
    fn validate_final_url_accepts_same_host() {
        let client = HttpClient::new().unwrap();
        let original = Url::parse("https://example.com/path1").unwrap();
        let final_url = Url::parse("https://example.com/path2").unwrap();
        let result = client.validate_final_url(&original, &final_url);
        assert!(result.is_ok());
    }
}
