use reqwest::{Client, Response};
use std::time::{Duration, Instant};

use super::hmac_signer::{HmacSigner, format_signature_header};
use super::subscription::WebhookAuth;
use crate::error::HttpClientError;

/// Default HTTP timeout applied when constructing a client via [`WebhookHttpClient::new`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP client wrapper for webhook delivery
pub struct WebhookHttpClient {
    client: Client,
}

impl WebhookHttpClient {
    /// Create a new HTTP client with the default timeout ([`DEFAULT_TIMEOUT`]).
    pub fn new() -> Result<Self, HttpClientError> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// Create a new HTTP client with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Result<Self, HttpClientError> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| HttpClientError::RequestFailed(e.to_string()))?;

        Ok(Self { client })
    }

    /// Send a webhook POST request.
    ///
    /// Returns `(status_code, response_time_ms, body)` on success.
    pub async fn send_webhook(
        &self,
        url: &str,
        payload: &str,
        auth: &WebhookAuth,
    ) -> Result<(u16, u64, String), HttpClientError> {
        let start = Instant::now();

        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json");

        request = self.add_auth_headers(request, payload, auth)?;

        let response = request
            .body(payload.to_string())
            .send()
            .await
            .map_err(HttpClientError::from)?;

        let response_time_ms = start.elapsed().as_millis() as u64;
        let status = response.status();
        let status_code = status.as_u16();

        let body = self.read_response_body(response).await?;

        if !status.is_success() {
            return Err(HttpClientError::ResponseError {
                status,
                body: body.clone(),
            });
        }

        Ok((status_code, response_time_ms, body))
    }

    fn add_auth_headers(
        &self,
        mut request: reqwest::RequestBuilder,
        payload: &str,
        auth: &WebhookAuth,
    ) -> Result<reqwest::RequestBuilder, HttpClientError> {
        match auth {
            WebhookAuth::None => {}
            WebhookAuth::HmacSha256 {
                secret,
                header_name,
            } => {
                use secrecy::ExposeSecret;
                let signer = HmacSigner::new(secret.expose_secret().to_vec());
                let (signature, timestamp) = signer
                    .sign(payload)
                    .map_err(|e| HttpClientError::SignatureError(e.to_string()))?;

                let header_value = format_signature_header(&signature, timestamp)
                    .map_err(|e| HttpClientError::SignatureError(e.to_string()))?;

                request = request.header(header_name.as_str(), header_value);
            }
            WebhookAuth::BearerToken { token } => {
                use secrecy::ExposeSecret;
                request =
                    request.header("Authorization", format!("Bearer {}", token.expose_secret()));
            }
        }

        Ok(request)
    }

    async fn read_response_body(&self, response: Response) -> Result<String, HttpClientError> {
        response.text().await.map_err(|e| {
            HttpClientError::RequestFailed(format!("Failed to read response body: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn test_http_client_creation() -> Result<(), HttpClientError> {
        let _client = WebhookHttpClient::new()?;
        Ok(())
    }

    #[test]
    fn test_http_client_error_display() {
        let err = HttpClientError::Timeout(DEFAULT_TIMEOUT);
        assert_eq!(err.to_string(), "Request timeout after 30s");

        let err = HttpClientError::InvalidUrl("invalid".to_string());
        assert_eq!(err.to_string(), "Invalid URL: invalid");

        let err = HttpClientError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "Network error: connection refused");

        let err = HttpClientError::SignatureError("time went backwards".to_string());
        assert_eq!(
            err.to_string(),
            "Failed to sign request: time went backwards"
        );
    }

    #[test]
    fn test_response_error_format() {
        let err = HttpClientError::ResponseError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "Server error".to_string(),
        };

        let error_msg = err.to_string();
        assert!(error_msg.contains("500"));
        assert!(error_msg.contains("Server error"));
    }
}
