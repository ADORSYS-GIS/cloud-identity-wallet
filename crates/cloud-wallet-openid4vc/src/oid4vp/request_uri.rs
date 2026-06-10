use crate::oid4vp::RequestUriError;
use crate::oid4vp::authorization::RequestUriMethod;
use crate::oid4vp::metadata::wallet::WalletPresentationMetadata;
use base64::Engine;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use url::Url;

/// Content type for the Request Object response as defined in RFC 9101 and OpenID4VP.
pub const OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE: &str = "application/oauth-authz-req+jwt";

/// Content type for form-urlencoded requests.
pub const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Response from the Request URI endpoint containing the Request Object JWT.
///
/// Per [OpenID4VP Section 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1),
/// a successful response returns the Request Object as a JWT with content type
/// `application/oauth-authz-req+jwt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUriResponse {
    /// The Request Object as a JWT string.
    pub jwt: String,
}

impl RequestUriResponse {
    /// Creates a new RequestUriResponse with the given JWT.
    pub fn new(jwt: impl Into<String>) -> Self {
        Self { jwt: jwt.into() }
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

/// Resolves a Request URI using HTTP GET.
///
/// Per [OpenID4VP Section 5.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1),
/// sends an HTTP GET request to the `request_uri` endpoint and returns the
/// Request Object JWT on success.
pub async fn resolve_request_uri_get(
    client: &ClientWithMiddleware,
    uri: &Url,
) -> Result<String, RequestUriError> {
    validate_https_scheme(uri)?;

    let response = client
        .get(uri.as_str())
        .header(ACCEPT, OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE)
        .send()
        .await
        .map_err(|e| RequestUriError::Transport(e.to_string()))?;

    handle_response(response).await
}

/// Resolves a Request URI using HTTP POST with wallet metadata.
///
/// Per [OpenID4VP Section 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10),
/// the Wallet sends an HTTP POST request to the `request_uri` endpoint with:
/// - `wallet_metadata`: OPTIONAL. JSON-encoded wallet capabilities
/// - `wallet_nonce`: OPTIONAL. Nonce for replay attack mitigation
///
/// Per Section 5.10.1, if a `wallet_nonce` was sent in the request, the Wallet
/// MUST validate that the returned Request Object contains the same nonce in
/// the `wallet_nonce` claim.
pub async fn resolve_request_uri_post(
    client: &ClientWithMiddleware,
    uri: &Url,
    wallet_metadata: &WalletPresentationMetadata,
    wallet_nonce: Option<&str>,
) -> Result<String, RequestUriError> {
    validate_https_scheme(uri)?;

    // Serialize wallet metadata to JSON
    let wallet_metadata_json = serde_json::to_string(wallet_metadata).map_err(|e| {
        RequestUriError::Serialization(format!("failed to serialize wallet_metadata: {e}"))
    })?;

    // Build POST parameters
    let params = RequestUriPostParams {
        wallet_metadata: Some(wallet_metadata_json),
        wallet_nonce: wallet_nonce.map(String::from),
    };

    // Serialize to form-urlencoded
    let form_body = serde_urlencoded::to_string(&params).map_err(|e| {
        RequestUriError::Serialization(format!("failed to serialize form parameters: {e}"))
    })?;

    let response = client
        .post(uri.as_str())
        .header(CONTENT_TYPE, FORM_URLENCODED_CONTENT_TYPE)
        .header(ACCEPT, OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE)
        .body(form_body)
        .send()
        .await
        .map_err(|e| RequestUriError::Transport(e.to_string()))?;

    let jwt = handle_response(response).await?;

    // If a wallet_nonce was sent, validate it in the response
    if let Some(expected_nonce) = wallet_nonce {
        validate_wallet_nonce(&jwt, expected_nonce)?;
    }

    Ok(jwt)
}

/// Resolves a Request URI using the specified method.
///
/// Dispatches to GET or POST based on the `method` parameter. Defaults to GET
/// if the method is not specified differently.
pub async fn resolve_request_uri(
    client: &ClientWithMiddleware,
    uri: &Url,
    method: RequestUriMethod,
    wallet_metadata: &Option<WalletPresentationMetadata>,
) -> Result<String, RequestUriError> {
    match method {
        RequestUriMethod::Get => resolve_request_uri_get(client, uri).await,
        RequestUriMethod::Post => {
            // For POST, wallet_metadata is required per the spec workflow
            let metadata = wallet_metadata.as_ref().ok_or_else(|| {
                RequestUriError::ValidationError(
                    "wallet_metadata is required for POST method".to_string(),
                )
            })?;

            resolve_request_uri_post_without_nonce(client, uri, metadata).await
        }
    }
}

/// Internal POST implementation without nonce validation for use by resolve_request_uri.
/// This is needed because resolve_request_uri doesn't have access to the wallet_nonce parameter
/// per the ticket specification.
async fn resolve_request_uri_post_without_nonce(
    client: &ClientWithMiddleware,
    uri: &Url,
    wallet_metadata: &WalletPresentationMetadata,
) -> Result<String, RequestUriError> {
    validate_https_scheme(uri)?;

    let wallet_metadata_json = serde_json::to_string(wallet_metadata).map_err(|e| {
        RequestUriError::Serialization(format!("failed to serialize wallet_metadata: {e}"))
    })?;

    let params = RequestUriPostParams {
        wallet_metadata: Some(wallet_metadata_json),
        wallet_nonce: None,
    };

    let form_body = serde_urlencoded::to_string(&params).map_err(|e| {
        RequestUriError::Serialization(format!("failed to serialize form parameters: {e}"))
    })?;

    let response = client
        .post(uri.as_str())
        .header(CONTENT_TYPE, FORM_URLENCODED_CONTENT_TYPE)
        .header(ACCEPT, OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE)
        .body(form_body)
        .send()
        .await
        .map_err(|e| RequestUriError::Transport(e.to_string()))?;

    handle_response(response).await
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
///
/// Per [OpenID4VP Section 5.10.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.2),
/// if the Verifier responds with any HTTP error response, the Wallet MUST
/// terminate the process. This function returns an error for any non-200 status.
///
/// Returns the JWT string on success (HTTP 200 with correct content type).
async fn handle_response(response: reqwest::Response) -> Result<String, RequestUriError> {
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

    // Per Section 5.10.2: HTTP error responses MUST terminate the process
    if status != StatusCode::OK {
        return Err(RequestUriError::HttpError {
            status: status.as_u16(),
            body,
        });
    }

    // Validate content type for successful responses
    if content_type != OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE {
        return Err(RequestUriError::InvalidContentType {
            expected: OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE.to_string(),
            actual: content_type,
        });
    }

    Ok(body.trim().to_string())
}

/// Validates that the wallet_nonce claim in the JWT matches the expected value.
///
/// Per [OpenID4VP Section 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1),
/// if the Wallet passed a wallet_nonce in the POST request, the Wallet MUST
/// validate whether the request object contains the respective nonce value
/// in a wallet_nonce claim.
fn validate_wallet_nonce(jwt: &str, expected_nonce: &str) -> Result<(), RequestUriError> {
    // Parse the JWT payload (middle segment)
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return Err(RequestUriError::DecodingFailed(
            "invalid JWT format: expected at least 2 segments".to_string(),
        ));
    }

    // Decode the payload (base64url encoded)
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| {
            RequestUriError::DecodingFailed(format!("failed to decode JWT payload: {e}"))
        })?;

    // Parse as JSON
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|e| {
        RequestUriError::DecodingFailed(format!("failed to parse JWT payload: {e}"))
    })?;

    // Extract the wallet_nonce claim
    let actual_nonce = payload
        .get("wallet_nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RequestUriError::WalletNonceMismatch {
            expected: expected_nonce.to_string(),
            actual: "missing".to_string(),
        })?;

    if actual_nonce != expected_nonce {
        return Err(RequestUriError::WalletNonceMismatch {
            expected: expected_nonce.to_string(),
            actual: actual_nonce.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::oid4vci::metadata::AuthorizationServerMetadata;
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

        let mock_response = ResponseTemplate::new(200)
            .set_body_bytes(jwt.clone().into_bytes())
            .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE);

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(mock_response)
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        assert!(result.is_ok(), "Expected Ok but got {:?}", result);
        assert_eq!(result.unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_invalid_content_type() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(create_test_jwt_without_nonce()),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidContentType { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_http_error_terminates() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        // Per Section 5.10.2, HTTP errors MUST terminate (return Err)
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::HttpError { status: 500, .. }
        ));
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
            resolve_request_uri_post(&client, &uri, &wallet_metadata, Some(wallet_nonce)).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_without_nonce() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let jwt = create_test_jwt_without_nonce();

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

        let result = resolve_request_uri_post(&client, &uri, &wallet_metadata, None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_nonce_mismatch() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let sent_nonce = "sent-nonce-123";
        let returned_nonce = "different-nonce";
        let jwt = create_test_jwt_with_nonce(returned_nonce);

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
            resolve_request_uri_post(&client, &uri, &wallet_metadata, Some(sent_nonce)).await;

        // Should fail because nonce doesn't match
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::WalletNonceMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_missing_nonce_claim() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let jwt = create_test_jwt_without_nonce();

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
            resolve_request_uri_post(&client, &uri, &wallet_metadata, Some("expected-nonce")).await;

        // Should fail because wallet_nonce claim is missing
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::WalletNonceMismatch { .. }
        ));
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

        let result = resolve_request_uri_post(&client, &uri, &wallet_metadata, None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidContentType { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_http_error_terminates() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_post(&client, &uri, &wallet_metadata, None).await;

        // Per Section 5.10.2, HTTP errors MUST terminate (return Err)
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::HttpError { status: 400, .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_invalid_scheme() {
        let client = create_test_client();
        let uri = Url::parse("http://example.com/request").unwrap();
        let wallet_metadata = create_test_wallet_metadata();

        let result = resolve_request_uri_post(&client, &uri, &wallet_metadata, None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidScheme
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_dispatch_get() {
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

        let result = resolve_request_uri(&client, &uri, RequestUriMethod::Get, &None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_dispatch_post() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let jwt = create_test_jwt_without_nonce();

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
            RequestUriMethod::Post,
            &Some(wallet_metadata),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_missing_wallet_metadata() {
        let client = create_test_client();
        let uri = Url::parse("https://example.com/request").unwrap();

        let result = resolve_request_uri(&client, &uri, RequestUriMethod::Post, &None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::ValidationError(_)
        ));
    }

    #[test]
    fn test_request_uri_method_default() {
        assert_eq!(RequestUriMethod::default(), RequestUriMethod::Get);
    }

    #[test]
    fn test_request_uri_method_serde() {
        let get = serde_json::to_string(&RequestUriMethod::Get).unwrap();
        assert_eq!(get, "\"get\"");

        let post = serde_json::to_string(&RequestUriMethod::Post).unwrap();
        assert_eq!(post, "\"post\"");

        let de_get: RequestUriMethod = serde_json::from_str("\"get\"").unwrap();
        assert_eq!(de_get, RequestUriMethod::Get);

        let de_post: RequestUriMethod = serde_json::from_str("\"post\"").unwrap();
        assert_eq!(de_post, RequestUriMethod::Post);
    }

    #[test]
    fn test_validate_https_scheme_success() {
        let uri = Url::parse("https://example.com/request").unwrap();
        assert!(validate_https_scheme(&uri).is_ok());
    }

    #[test]
    fn test_validate_https_scheme_failure() {
        let uri = Url::parse("http://example.com/request").unwrap();
        assert!(validate_https_scheme(&uri).is_err());
    }

    #[tokio::test]
    async fn test_arbitrary_body_accepted_with_correct_content_type() {
        // Per spec, we validate content type but not JWT format
        // The body is returned as-is for higher layers to validate
        let mock_server = MockServer::start().await;
        let body_content = "arbitrary-body-content";

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(body_content.as_bytes().to_vec())
                    .append_header("content-type", OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        // Body is returned as-is; JWT validation happens at higher layer
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body_content);
    }

    #[tokio::test]
    async fn test_content_type_with_charset() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt_without_nonce();

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(jwt.clone().into_bytes())
                    .append_header(
                        "content-type",
                        "application/oauth-authz-req+jwt; charset=utf-8",
                    ),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), jwt);
    }

    #[test]
    fn test_request_uri_response_struct() {
        let jwt = "test.jwt.string";
        let response = RequestUriResponse::new(jwt);
        assert_eq!(response.jwt, jwt);
        assert_eq!(response.into_jwt(), jwt);
    }

    #[test]
    fn test_validate_wallet_nonce_success() {
        let nonce = "test-nonce-123";
        let jwt = create_test_jwt_with_nonce(nonce);
        assert!(validate_wallet_nonce(&jwt, nonce).is_ok());
    }

    #[test]
    fn test_validate_wallet_nonce_mismatch() {
        let jwt = create_test_jwt_with_nonce("actual-nonce");
        let result = validate_wallet_nonce(&jwt, "expected-nonce");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::WalletNonceMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_wallet_nonce_missing() {
        let jwt = create_test_jwt_without_nonce();
        let result = validate_wallet_nonce(&jwt, "expected-nonce");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::WalletNonceMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_wallet_nonce_invalid_jwt() {
        let result = validate_wallet_nonce("invalid-jwt", "nonce");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::DecodingFailed(_)
        ));
    }
}
