use super::RequestUriMethod;
use crate::oid4vp::metadata::wallet::WalletPresentationMetadata;
use crate::oid4vp::{AuthorizationErrorResponse, RequestUriError};
use reqwest::StatusCode;
use reqwest::header::ACCEPT;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use url::Url;

/// Content type for the Request Object response as defined in RFC 9101 and OpenID4VP.
pub const OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE: &str = "application/oauth-authz-req+jwt";

/// Result from Request URI resolution, including the JWT and context for later validation.
///
/// Per [OpenID4VP Section 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1),
/// if a `wallet_nonce` was sent in the POST request, the Wallet MUST validate that the
/// returned Request Object contains the same nonce in a `wallet_nonce` claim. This
/// validation MUST happen after the Request Object has been signature-verified or
/// decrypted (per RFC 9101 processing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriResult {
    pub jwt: String,

    pub expected_wallet_nonce: Option<String>,
}

impl RequestUriResult {
    /// Creates a new RequestUriResult with the given JWT and optional expected nonce.
    pub fn new(jwt: impl Into<String>, expected_wallet_nonce: Option<String>) -> Self {
        Self {
            jwt: jwt.into(),
            expected_wallet_nonce,
        }
    }

    /// Returns the JWT string.
    pub fn into_jwt(self) -> String {
        self.jwt
    }
}

/// Parameters sent in a POST request to the Request URI endpoint.
///
/// Per [OpenID4VP Section 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10),
/// the POST body includes:
/// - `wallet_metadata`: OPTIONAL. JSON-encoded wallet capabilities
/// - `wallet_nonce`: OPTIONAL. Nonce for replay attack mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestUriPostParams {
    /// JSON-encoded wallet metadata (optional per Section 5.10).
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_metadata: Option<String>,
    /// Optional nonce for replay attack mitigation.
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_nonce: Option<String>,
}

impl RequestUriPostParams {
    /// Creates new POST parameters with the given metadata and nonce.
    fn new(wallet_metadata: Option<String>, wallet_nonce: Option<String>) -> Self {
        Self {
            wallet_metadata,
            wallet_nonce,
        }
    }
}

/// Resolves a Request URI using HTTP GET.
///
/// Per [OpenID4VP Section 5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1),
/// sends an HTTP GET request to the `request_uri` endpoint and returns the
/// Request Object JWT on success.
pub async fn resolve_request_uri_get(
    client: &ClientWithMiddleware,
    uri: &Url,
) -> Result<RequestUriResult, RequestUriError> {
    validate_https_scheme(uri)?;

    let response = client
        .get(uri.as_str())
        .header(ACCEPT, OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE)
        .send()
        .await
        .map_err(|e| RequestUriError::Transport(e.to_string()))?;

    let jwt = handle_response(response).await?;
    Ok(RequestUriResult::new(jwt, None))
}

/// Resolves a Request URI using HTTP POST with optional wallet metadata and nonce.
///
/// Per [OpenID4VP Section 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10),
/// the Wallet sends an HTTP POST request to the `request_uri` endpoint with:
/// - `wallet_metadata`: OPTIONAL. JSON-encoded wallet capabilities
/// - `wallet_nonce`: OPTIONAL. Nonce for replay attack mitigation
pub async fn resolve_request_uri_post(
    client: &ClientWithMiddleware,
    uri: &Url,
    wallet_metadata: Option<&WalletPresentationMetadata>,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriResult, RequestUriError> {
    validate_https_scheme(uri)?;

    // Serialize wallet metadata to JSON if provided
    let wallet_metadata_json = wallet_metadata
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| {
            RequestUriError::Serialization(format!("failed to serialize wallet_metadata: {e}"))
        })?;

    // Build POST parameters using native reqwest form encoding
    let params = RequestUriPostParams::new(wallet_metadata_json, wallet_nonce.map(String::from));

    let response = client
        .post(uri.as_str())
        .header(ACCEPT, OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE)
        .form(&params)
        .send()
        .await
        .map_err(|e| RequestUriError::Transport(e.to_string()))?;

    let jwt = handle_response(response).await?;

    // Return the JWT along with the expected nonce for later validation
    // The orchestrator MUST validate the wallet_nonce claim after signature/decryption
    Ok(RequestUriResult::new(jwt, wallet_nonce.map(String::from)))
}

/// Resolves a Request URI using the specified method.
///
/// Per the OpenID4VP spec, if `method` is `None`, defaults to GET.
pub async fn resolve_request_uri(
    client: &ClientWithMiddleware,
    uri: &Url,
    method: Option<RequestUriMethod>,
    wallet_metadata: Option<&WalletPresentationMetadata>,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriResult, RequestUriError> {
    match method.unwrap_or_default() {
        RequestUriMethod::Get => resolve_request_uri_get(client, uri).await,
        RequestUriMethod::Post => {
            resolve_request_uri_post(client, uri, wallet_metadata, wallet_nonce).await
        }
    }
}

/// Validates that the URL uses HTTPS scheme.
///
/// Per [OpenID4VP Section 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10),
/// the POST request "MUST use the HTTP POST method with the https scheme".
fn validate_https_scheme(uri: &Url) -> Result<(), RequestUriError> {
    #[cfg(test)]
    {
        // Allow HTTP for localhost in tests
        if uri.scheme() == "http" && is_localhost(uri) {
            return Ok(());
        }
    }
    if uri.scheme() != "https" {
        return Err(RequestUriError::InvalidScheme);
    }
    Ok(())
}

/// Check if the URL is for a localhost/loopback address (for testing).
#[cfg(test)]
fn is_localhost(uri: &Url) -> bool {
    let host = uri.host_str().unwrap_or("");
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
}

/// Handles the HTTP response, validating status code and content type.
async fn handle_response(response: reqwest::Response) -> Result<String, RequestUriError> {
    use reqwest::header::CONTENT_TYPE;

    let status = response.status();

    // Extract content type before consuming response
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            // Extract just the media type, ignoring charset and other parameters
            v.split(';').next().unwrap_or(v).trim()
        })
        .unwrap_or("")
        .to_string();

    // Extract the response body (this consumes the response)
    let body = response
        .text()
        .await
        .map_err(|e| RequestUriError::Transport(format!("failed to read response body: {e}")))?;

    // Per Section 5.10.2: HTTP error responses MUST terminate the process.
    // As a diagnostic convenience, we attempt to parse a structured error response
    // (similar to OAuth 2.0 error format), but this is not defined by the spec.
    if status != StatusCode::OK {
        if let Ok(error_response) = serde_json::from_str::<AuthorizationErrorResponse>(&body) {
            return Err(RequestUriError::AuthorizationError {
                error: error_response,
                status: status.as_u16(),
            });
        }

        // Fallback to generic HTTP error if parsing fails
        return Err(RequestUriError::HttpError {
            status: status.as_u16(),
            body,
        });
    }

    // Validate content type for successful responses (case-insensitive per RFC 7231)
    if !content_type.eq_ignore_ascii_case(OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE) {
        return Err(RequestUriError::InvalidContentType {
            expected: OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE.to_string(),
            actual: content_type,
        });
    }

    Ok(body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::oid4vci::metadata::AuthorizationServerMetadata;
    use crate::oid4vp::AuthorizationErrorCode;
    use crate::oid4vp::metadata::wallet::WalletPresentationMetadata;
    use crate::oid4vp::metadata::{
        CredentialFormatIdentifier, VpFormatCapability, VpFormatsSupported,
    };
    use std::collections::HashMap;

    /// Create a test HTTP client that accepts HTTP URLs (for mock server testing).
    fn create_test_client() -> ClientWithMiddleware {
        let inner_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build test client");
        ClientBuilder::new(inner_client).build()
    }

    fn create_test_wallet_metadata() -> WalletPresentationMetadata {
        let as_metadata = AuthorizationServerMetadata {
            issuer: Url::parse("https://wallet.example.com").unwrap(),
            authorization_endpoint: Some(
                Url::parse("https://wallet.example.com/authorize").unwrap(),
            ),
            token_endpoint: Some(Url::parse("https://wallet.example.com/token").unwrap()),
            jwks_uri: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: Some(vec!["vp_token".to_string()]),
            response_modes_supported: None,
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            service_documentation: None,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: None,
            pre_authorized_grant_anonymous_access_supported: None,
            authorization_details_types_supported: None,
            extra_fields: HashMap::new(),
        };

        let mut vp_formats = VpFormatsSupported::new();
        let mut format_capability = HashMap::new();
        format_capability.insert("sd-jwt_alg_values".to_string(), json![["ES256"]]);
        vp_formats.insert(
            CredentialFormatIdentifier::DcSdJwt,
            VpFormatCapability::Other(format_capability),
        );

        WalletPresentationMetadata::new(as_metadata, vp_formats)
    }

    /// Create a test JWT with a wallet_nonce claim in the payload.
    fn create_test_jwt_with_nonce(nonce: &str) -> String {
        // Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
        let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ";
        // Payload with the specified nonce
        let payload_obj = json!({
            "client_id": "x509_san_dns:client.example.org",
            "response_type": "vp_token",
            "wallet_nonce": nonce
        });
        let payload_bytes = serde_json::to_vec(&payload_obj).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signature = "signature";
        format!("{}.{}.{}", header, payload, signature)
    }

    /// Create a test JWT without a wallet_nonce claim.
    fn create_test_jwt_without_nonce() -> String {
        // Header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
        let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ";
        // Payload without wallet_nonce
        let payload_obj = json!({
            "client_id": "x509_san_dns:client.example.org",
            "response_type": "vp_token"
        });
        let payload_bytes = serde_json::to_vec(&payload_obj).unwrap();
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signature = "signature";
        format!("{}.{}.{}", header, payload, signature)
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_success() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt_without_nonce();

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        assert!(result.is_ok(), "Expected Ok but got {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, None);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_invalid_scheme() {
        let client = create_test_client();
        let uri = Url::parse("http://example.com/request").unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidScheme
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_success() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let wallet_nonce = "test-nonce-123";
        let jwt = create_test_jwt_with_nonce(wallet_nonce);

        Mock::given(method("POST"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result =
            resolve_request_uri_post(&client, &uri, Some(&wallet_metadata), Some(wallet_nonce))
                .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.jwt, jwt);
        // Per Section 5.10.1, the orchestrator MUST validate this nonce after
        // the Request Object has been signature-verified or decrypted
        assert_eq!(result.expected_wallet_nonce, Some(wallet_nonce.to_string()));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_invalid_content_type() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/plain")
                    .set_body_string(create_test_jwt_without_nonce()),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_post(&client, &uri, Some(&wallet_metadata), None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidContentType { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_http_error() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();

        // Test HTTP error without AuthorizationErrorResponse
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_post(&client, &uri, Some(&wallet_metadata), None).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::HttpError { status: 400, .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_authorization_error_response() {
        // Test that we can parse a structured error response as a diagnostic convenience
        // (Section 5.10.2 requires termination but doesn't define the response format)
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();

        let error_response = serde_json::json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter",
            "state": "abc123"
        });

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(error_response.to_string())
                    .insert_header("content-type", "application/json"),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_post(&client, &uri, Some(&wallet_metadata), None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RequestUriError::AuthorizationError { error, status } => {
                assert_eq!(status, 400);
                assert_eq!(error.error, AuthorizationErrorCode::InvalidRequest);
                assert_eq!(
                    error.error_description,
                    Some("Missing required parameter".to_string())
                );
                assert_eq!(error.state, Some("abc123".to_string()));
            }
            other => panic!("Expected AuthorizationError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_resolve_request_uri_dispatch_post_with_nonce() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let wallet_nonce = "test-nonce-456";
        let jwt = create_test_jwt_with_nonce(wallet_nonce);

        Mock::given(method("POST"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri(
            &client,
            &uri,
            Some(RequestUriMethod::Post),
            Some(&wallet_metadata),
            Some(wallet_nonce),
        )
        .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, Some(wallet_nonce.to_string()));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_without_wallet_metadata() {
        // Per spec Section 5.10, wallet_metadata is OPTIONAL for POST
        let mock_server = MockServer::start().await;
        let wallet_nonce = "test-nonce-789";
        let jwt = create_test_jwt_with_nonce(wallet_nonce);

        Mock::given(method("POST"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        // POST without wallet_metadata should succeed per the spec
        let result = resolve_request_uri_post(&client, &uri, None, Some(wallet_nonce)).await;

        assert!(result.is_ok(), "Expected Ok but got {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, Some(wallet_nonce.to_string()));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_defaults_to_get() {
        // Test that when method is None, it defaults to GET
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt_without_nonce();

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        // Pass None for method - should default to GET
        let result = resolve_request_uri(&client, &uri, None, None, None).await;

        assert!(result.is_ok(), "Expected Ok but got {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, None);
    }

    #[test]
    fn test_request_uri_result_struct() {
        let jwt = "test.jwt.string";

        // Without expected nonce
        let result = RequestUriResult::new(jwt, None);
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, None);

        // With expected nonce
        let nonce = "test-nonce-123";
        let result = RequestUriResult::new(jwt, Some(nonce.to_string()));
        assert_eq!(result.jwt, jwt);
        assert_eq!(result.expected_wallet_nonce, Some(nonce.to_string()));
    }

    #[test]
    fn test_wallet_nonce_validation_helper() {
        // This helper is provided for orchestrators to validate wallet_nonce
        // after the Request Object has been signature-verified or decrypted
        let nonce = "test-nonce-123";
        let jwt = create_test_jwt_with_nonce(nonce);

        // Parse the JWT payload and validate nonce
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let actual_nonce = payload.get("wallet_nonce").and_then(|v| v.as_str());
        assert_eq!(actual_nonce, Some(nonce));
    }
}
