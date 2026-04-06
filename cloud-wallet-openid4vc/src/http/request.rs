//! HTTP request builders for JSON and form-encoded requests.

use std::marker::PhantomData;

use reqwest::header::HeaderValue;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::errors::{Error, ErrorKind};
use crate::http::client::HttpClient;
use crate::http::response::{JsonResponse, RawResponse};
use crate::http::{AuthHeader, HttpError};

/// Generic request builder for raw HTTP requests.
pub struct RequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    url: String,
    headers: reqwest::header::HeaderMap,
    body: Option<reqwest::Body>,
    auth: Option<AuthHeader>,
}

impl<'a> RequestBuilder<'a> {
    /// Creates a new request builder.
    #[must_use]
    pub fn new(client: &'a HttpClient, method: Method, url: &str) -> Self {
        Self {
            client,
            method,
            url: url.to_string(),
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            auth: None,
        }
    }

    /// Sets the authorization header.
    #[must_use]
    pub fn auth(mut self, auth: AuthHeader) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets a Bearer token authorization header.
    #[must_use]
    pub fn bearer(self, token: impl Into<String>) -> Self {
        self.auth(AuthHeader::bearer(token))
    }

    /// Adds a header to the request.
    #[must_use]
    pub fn header(mut self, key: &'static str, value: &str) -> Self {
        if let Ok(header_name) = reqwest::header::HeaderName::try_from(key)
            && let Ok(header_value) = HeaderValue::try_from(value) {
                self.headers.insert(header_name, header_value);
            }
        self
    }

    /// Sets the request body as raw bytes.
    #[must_use]
    pub fn body(mut self, body: impl Into<reqwest::Body>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Sets the request body as JSON.
    #[must_use]
    pub fn json<T: Serialize>(mut self, body: &T) -> Self {
        self.headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.body = Some(
            serde_json::to_vec(body)
                .expect("failed to serialize JSON body")
                .into(),
        );
        self
    }

    /// Sets the request body as form-encoded.
    #[must_use]
    pub fn form(mut self, body: impl Serialize) -> Self {
        self.headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let encoded = serde_urlencoded::to_string(&body).expect("failed to encode form body");
        self.body = Some(encoded.into());
        self
    }

    /// Executes the request and returns a raw response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request fails (network error, timeout, etc.)
    /// - The response status is not successful (4xx or 5xx)
    /// - The response body exceeds the size limit
    pub async fn send(self) -> Result<RawResponse, Error> {
        let mut request = self.client.inner.request(self.method, &self.url);

        if let Some(ref auth) = self.auth {
            let auth_header = auth.to_header_value()?;
            request = request.header(reqwest::header::AUTHORIZATION, auth_header);
            if let Some(additional) = auth.additional_headers() {
                for (name, value) in additional.iter() {
                    request = request.header(name, value);
                }
            }
        }

        request = request.headers(self.headers);

        if let Some(body) = self.body {
            request = request.body(body);
        }

        let response = self.client.execute_raw(request.build().unwrap()).await?;

        handle_raw_response(response, self.client.max_response_size).await
    }
}

/// Request builder for JSON requests with typed response.
pub struct JsonRequestBuilder<'a, T, B = serde_json::Value> {
    client: &'a HttpClient,
    method: Method,
    url: String,
    headers: reqwest::header::HeaderMap,
    body: Option<&'a B>,
    auth: Option<AuthHeader>,
    max_response_size: usize,
    _response: PhantomData<T>,
}

impl<'a, T: DeserializeOwned, B: Serialize> JsonRequestBuilder<'a, T, B> {
    /// Creates a new JSON request builder.
    #[must_use]
    pub fn new(client: &'a HttpClient, method: Method, url: &str) -> Self {
        Self {
            client,
            method,
            url: url.to_string(),
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            auth: None,
            max_response_size: client.max_response_size(),
            _response: PhantomData,
        }
    }

    /// Sets the request body.
    #[must_use]
    pub fn body(mut self, body: &'a B) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets the authorization header.
    #[must_use]
    pub fn auth(mut self, auth: AuthHeader) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets a Bearer token authorization header.
    #[must_use]
    pub fn bearer(self, token: impl Into<String>) -> Self {
        self.auth(AuthHeader::bearer(token))
    }

    /// Adds a header to the request.
    #[must_use]
    pub fn header(mut self, key: &'static str, value: &str) -> Self {
        if let Ok(header_name) = reqwest::header::HeaderName::try_from(key)
            && let Ok(header_value) = HeaderValue::try_from(value) {
                self.headers.insert(header_name, header_value);
            }
        self
    }

    /// Sets the maximum response size.
    #[must_use]
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.max_response_size = size;
        self
    }

    /// Executes the request and returns a parsed JSON response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request fails (network error, timeout, etc.)
    /// - The response status is not successful (4xx or 5xx)
    /// - The response body exceeds the size limit
    /// - The response body is not valid JSON
    /// - The JSON does not match the expected type
    pub async fn send(self) -> Result<JsonResponse<T>, Error> {
        let mut request = self.client.inner.request(self.method, &self.url);

        request = request.header(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );

        if let Some(ref auth) = self.auth {
            let auth_header = auth.to_header_value()?;
            request = request.header(reqwest::header::AUTHORIZATION, auth_header);
            if let Some(additional) = auth.additional_headers() {
                for (name, value) in additional.iter() {
                    request = request.header(name, value);
                }
            }
        }

        if let Some(body) = self.body {
            request = request.json(body);
        }

        request = request.headers(self.headers);

        let response = self.client.execute_raw(request.build().unwrap()).await?;

        handle_json_response(response, self.max_response_size).await
    }
}

impl<'a, T: DeserializeOwned> JsonRequestBuilder<'a, T, serde_json::Value> {
    /// Creates a GET request for JSON content.
    #[must_use]
    pub fn get(client: &'a HttpClient, url: &str) -> Self {
        Self::new(client, Method::GET, url)
    }
}

/// Request builder for form-encoded requests.
pub struct FormRequestBuilder<'a, T> {
    client: &'a HttpClient,
    url: String,
    headers: reqwest::header::HeaderMap,
    params: std::collections::HashMap<String, String>,
    auth: Option<AuthHeader>,
    max_response_size: usize,
    _response: PhantomData<T>,
}

impl<'a, T: DeserializeOwned> FormRequestBuilder<'a, T> {
    /// Creates a new form request builder.
    #[must_use]
    pub fn new(client: &'a HttpClient, url: &str) -> Self {
        Self {
            client,
            url: url.to_string(),
            headers: reqwest::header::HeaderMap::new(),
            params: std::collections::HashMap::new(),
            auth: None,
            max_response_size: client.max_response_size(),
            _response: PhantomData,
        }
    }

    /// Adds a parameter to the form body.
    #[must_use]
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// Adds multiple parameters to the form body.
    #[must_use]
    pub fn params<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (key, value) in params {
            self.params.insert(key.into(), value.into());
        }
        self
    }

    /// Sets the authorization header.
    #[must_use]
    pub fn auth(mut self, auth: AuthHeader) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets a Bearer token authorization header.
    #[must_use]
    pub fn bearer(self, token: impl Into<String>) -> Self {
        self.auth(AuthHeader::bearer(token))
    }

    /// Sets Basic authorization.
    #[must_use]
    pub fn basic(self, username: &str, password: &str) -> Self {
        self.auth(AuthHeader::basic(username, password))
    }

    /// Adds a header to the request.
    #[must_use]
    pub fn header(mut self, key: &'static str, value: &str) -> Self {
        if let Ok(header_name) = reqwest::header::HeaderName::try_from(key)
            && let Ok(header_value) = HeaderValue::try_from(value) {
                self.headers.insert(header_name, header_value);
            }
        self
    }

    /// Sets the maximum response size.
    #[must_use]
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.max_response_size = size;
        self
    }

    /// Executes the request and returns a parsed JSON response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request fails (network error, timeout, etc.)
    /// - The response status is not successful (4xx or 5xx)
    /// - The response body exceeds the size limit
    /// - The response body is not valid JSON
    /// - The JSON does not match the expected type
    pub async fn send(self) -> Result<JsonResponse<T>, Error> {
        let mut request = self.client.inner.post(&self.url);

        request = request.header(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );

        request = request.header(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        if let Some(ref auth) = self.auth {
            let auth_header = auth.to_header_value()?;
            request = request.header(reqwest::header::AUTHORIZATION, auth_header);
            if let Some(additional) = auth.additional_headers() {
                for (name, value) in additional.iter() {
                    request = request.header(name, value);
                }
            }
        }

        let encoded = serde_urlencoded::to_string(&self.params)
            .map_err(|e| Error::message(ErrorKind::HttpRequestFailed, format!("failed to encode form body: {e}")))?;
        request = request.body(encoded);

        request = request.headers(self.headers);

        let response = self.client.execute_raw(request.build().unwrap()).await?;

        handle_json_response(response, self.max_response_size).await
    }
}

async fn handle_raw_response(
    mut response: reqwest::Response,
    max_size: usize,
) -> Result<RawResponse, Error> {
    let status = response.status();
    let headers = response.headers().clone();
    let final_url = response.url().clone();

    let mut accumulated = Vec::with_capacity(1024);

    while let Ok(Some(chunk)) = response.chunk().await {
        if accumulated.len().saturating_add(chunk.len()) > max_size {
            return Err(Error::message(
                ErrorKind::HttpRequestFailed,
                format!("response body exceeds maximum allowed {} bytes", max_size),
            ));
        }
        accumulated.extend_from_slice(&chunk);
    }

    let body = String::from_utf8(accumulated).map_err(|e| {
        Error::message(
            ErrorKind::HttpResponseParsingFailed,
            format!("response body is not valid UTF-8: {e}"),
        )
    })?;

    if !status.is_success() {
        return Err(Error::new(
            ErrorKind::HttpErrorResponse,
            HttpError::new(status, Some(body), headers),
        ));
    }

    Ok(RawResponse {
        status,
        headers,
        body: Some(body),
        final_url,
    })
}

async fn handle_json_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_size: usize,
) -> Result<JsonResponse<T>, Error> {
    let status = response.status();
    let headers = response.headers().clone();
    let final_url = response.url().clone();

    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let media_type = content_type.split(';').next().unwrap_or("").trim();

    let mut accumulated = Vec::with_capacity(1024);

    while let Ok(Some(chunk)) = response.chunk().await {
        if accumulated.len().saturating_add(chunk.len()) > max_size {
            return Err(Error::message(
                ErrorKind::HttpRequestFailed,
                format!("response body exceeds maximum allowed {} bytes", max_size),
            ));
        }
        accumulated.extend_from_slice(&chunk);
    }

    let body = String::from_utf8(accumulated).map_err(|e| {
        Error::message(
            ErrorKind::HttpResponseParsingFailed,
            format!("response body is not valid UTF-8: {e}"),
        )
    })?;

    if !status.is_success() {
        return Err(Error::new(
            ErrorKind::HttpErrorResponse,
            HttpError::new(status, Some(body), headers),
        ));
    }

    if media_type != "application/json" && media_type != "application/jwt" {
        return Err(Error::message(
            ErrorKind::HttpResponseParsingFailed,
            format!("expected media type application/json, got '{}'", media_type),
        ));
    }

    let parsed: T = serde_json::from_str(&body).map_err(|e| {
        Error::message(
            ErrorKind::HttpResponseParsingFailed,
            format!("failed to parse JSON response: {e}"),
        )
    })?;

    Ok(JsonResponse {
        status,
        headers,
        body: parsed,
        raw: Some(body),
        final_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> HttpClient {
        HttpClientBuilder::new()
            .accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    use crate::http::client::HttpClientBuilder;

    #[test]
    fn request_builder_sets_bearer_auth() {
        let client = test_client();
        let builder = RequestBuilder::new(&client, Method::GET, "https://example.com")
            .bearer("test-token");
        assert!(builder.auth.is_some());
    }

    #[test]
    fn request_builder_sets_header() {
        let client = test_client();
        let builder = RequestBuilder::new(&client, Method::GET, "https://example.com")
            .header("X-Custom", "value");
        assert!(builder.headers.contains_key("x-custom"));
    }

    #[test]
    fn json_request_builder_sets_body() {
        let client = test_client();
        let body = serde_json::json!({"key": "value"});
        let builder = JsonRequestBuilder::<serde_json::Value>::new(
            &client,
            Method::POST,
            "https://example.com",
        )
        .body(&body);
        assert!(builder.body.is_some());
    }

    #[test]
    fn form_request_builder_adds_params() {
        let client = test_client();
        let builder = FormRequestBuilder::<serde_json::Value>::new(&client, "https://example.com")
            .param("grant_type", "authorization_code")
            .param("code", "abc123");
        assert_eq!(builder.params.len(), 2);
        assert_eq!(builder.params.get("grant_type"), Some(&"authorization_code".to_string()));
    }

    #[test]
    fn auth_header_bearer_format() {
        let auth = AuthHeader::bearer("test-token");
        let value = auth.to_header_value().unwrap();
        assert_eq!(value.to_str().unwrap(), "Bearer test-token");
    }

    #[test]
    fn auth_header_basic_format() {
        let auth = AuthHeader::basic("user", "pass");
        let value = auth.to_header_value().unwrap();
        assert!(value.to_str().unwrap().starts_with("Basic "));
    }

    #[test]
    fn auth_header_dpop_format() {
        let auth = AuthHeader::dpop("test-token", "test-proof");
        let value = auth.to_header_value().unwrap();
        assert_eq!(value.to_str().unwrap(), "DPoP test-token");

        let headers = auth.additional_headers().unwrap();
        assert!(headers.contains_key("dpop"));
    }
}
