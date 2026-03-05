use crate::error::SignatureError;
use reqwest::{Client, Response, StatusCode};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

use super::hmac_signer::{HmacSigner, format_signature_header};
use super::subscription::WebhookAuth;

/// Error type for HTTP client operations
#[derive(Debug, Error)]
pub enum HttpClientError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    #[error("Request timed out: {0}")]
    Timeout(String),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Response error: status={status}, body={body}")]
    ResponseError { status: StatusCode, body: String },

    #[error(transparent)]
    Signature(#[from] SignatureError),
}

impl From<reqwest::Error> for HttpClientError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            HttpClientError::Timeout(err.to_string())
        } else if err.is_connect() {
            HttpClientError::NetworkError(err.to_string())
        } else {
            HttpClientError::RequestFailed(err.to_string())
        }
    }
}

/// HTTP client wrapper for webhook delivery
pub struct WebhookHttpClient {
    client: Client,
}

impl WebhookHttpClient {
    /// Create a new HTTP client with default timeout (30 seconds)
    pub fn new() -> Result<Self, HttpClientError> {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new HTTP client with custom timeout
    pub fn with_timeout(timeout: Duration) -> Result<Self, HttpClientError> {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(format!("WalletEvents/{}", env!("CARGO_PKG_VERSION")))
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
        debug!(url = %url, "Sending webhook");

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
            .map_err(|e| {
                warn!(url = %url, error = %e, "Webhook request failed");
                HttpClientError::from(e)
            })?;

        let elapsed = start.elapsed();
        let response_time_ms = elapsed.as_millis() as u64;
        let status = response.status();
        let status_code = status.as_u16();

        debug!(
            url = %url,
            status = %status_code,
            response_time_ms = %response_time_ms,
            "Webhook response received"
        );

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
            WebhookAuth::HmacSha256 { secret } => {
                let signer = HmacSigner::new(secret.clone());
                let (signature, timestamp) = signer
                    .sign(payload)
                    .map_err(|e| SignatureError::SigningFailed(e.to_string()))?;

                request = request
                    .header("X-Webhook-Signature", format_signature_header(&signature))
                    .header("X-Webhook-Timestamp", timestamp.to_string());
            }
            WebhookAuth::BearerToken { token } => {
                request = request.header("Authorization", format!("Bearer {}", token));
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

    #[test]
    fn test_http_client_creation() -> Result<(), HttpClientError> {
        let _client = WebhookHttpClient::new()?;
        Ok(())
    }

    #[test]
    fn test_http_client_error_display() {
        let err = HttpClientError::Timeout("operation timed out".to_string());
        assert!(err.to_string().contains("timed out"));

        let err = HttpClientError::InvalidUrl("invalid".to_string());
        assert_eq!(err.to_string(), "Invalid URL: invalid");

        let err = HttpClientError::NetworkError("connection refused".to_string());
        assert_eq!(err.to_string(), "Network error: connection refused");

        let err = HttpClientError::Signature(SignatureError::SigningFailed(
            "time went backwards".to_string(),
        ));
        assert!(err.to_string().contains("time went backwards"));
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