use crate::oid4vp::RequestUriError;
use crate::oid4vp::authorization::RequestUriMethod;
use crate::oid4vp::error::AuthorizationErrorResponse;
use crate::oid4vp::metadata::wallet::WalletPresentationMetadata;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use url::Url;

/// Content type for the Request Object response as defined in RFC 9101 and OpenID4VP.
pub const OAUTH_AUTHZ_REQ_JWT_CONTENT_TYPE: &str = "application/oauth-authz-req+jwt";

/// Content type for form-urlencoded requests.
pub const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Response from the Request URI endpoint.
///
/// Per [OpenID4VP Section 5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1),
/// a successful response returns the Request Object as a JWT with content type
/// `application/oauth-authz-req+jwt`.
///
/// Per [OpenID4VP Section 5.10.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.2),
/// an error response returns an OAuth 2.0 error with content type `application/json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestUriResponse {
    /// Successful response containing the Request Object JWT.
    Success(String),
    /// Error response containing the authorization error.
    Error(AuthorizationErrorResponse),
}

impl RequestUriResponse {
    /// Returns the JWT if the response is successful, or an error if it's an authorization error.
    pub fn into_jwt(self) -> Result<String, AuthorizationErrorResponse> {
        match self {
            RequestUriResponse::Success(jwt) => Ok(jwt),
            RequestUriResponse::Error(err) => Err(err),
        }
    }

    /// Returns true if this is a successful response.
    pub fn is_success(&self) -> bool {
        matches!(self, RequestUriResponse::Success(_))
    }

    /// Returns true if this is an error response.
    pub fn is_error(&self) -> bool {
        matches!(self, RequestUriResponse::Error(_))
    }
}

/// Parameters sent in a POST request to the Request URI endpoint.
///
/// Per [OpenID4VP Section 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10),
/// the POST body includes:
/// - `client_id`: REQUIRED. The client_id of the Wallet
/// - `wallet_metadata`: OPTIONAL. JSON-encoded wallet capabilities
/// - `wallet_nonce`: OPTIONAL. Nonce for replay attack mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestUriPostParams {
    /// The client_id of the Wallet (REQUIRED per Section 5.10).
    client_id: String,
    /// JSON-encoded wallet metadata (optional per Section 5.10).
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_metadata: Option<String>,
    /// Optional nonce for replay attack mitigation.
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_nonce: Option<String>,
}

/// Resolves a Request URI using HTTP GET.
pub async fn resolve_request_uri_get(
    client: &ClientWithMiddleware,
    uri: &Url,
) -> Result<RequestUriResponse, RequestUriError> {
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
/// - `client_id`: REQUIRED. The client_id of the Wallet
/// - `wallet_metadata`: OPTIONAL. JSON-encoded wallet capabilities
/// - `wallet_nonce`: OPTIONAL. Nonce for replay attack mitigation
pub async fn resolve_request_uri_post(
    client: &ClientWithMiddleware,
    uri: &Url,
    client_id: &str,
    wallet_metadata: Option<&WalletPresentationMetadata>,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriResponse, RequestUriError> {
    validate_https_scheme(uri)?;

    // Serialize wallet metadata to JSON if provided
    let wallet_metadata_json = wallet_metadata
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| {
            RequestUriError::Serialization(format!("failed to serialize wallet_metadata: {e}"))
        })?;

    // Build POST parameters
    let params = RequestUriPostParams {
        client_id: client_id.to_string(),
        wallet_metadata: wallet_metadata_json,
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

    handle_response(response).await
}

/// Resolves a Request URI using the specified method.
pub async fn resolve_request_uri(
    client: &ClientWithMiddleware,
    uri: &Url,
    method: RequestUriMethod,
    client_id: Option<&str>,
    wallet_metadata: Option<&WalletPresentationMetadata>,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriResponse, RequestUriError> {
    match method {
        RequestUriMethod::Get => resolve_request_uri_get(client, uri).await,
        RequestUriMethod::Post => {
            let cid = client_id.ok_or_else(|| {
                RequestUriError::Serialization(
                    "client_id is required for POST method per Section 5.10".to_string(),
                )
            })?;
            resolve_request_uri_post(client, uri, cid, wallet_metadata, wallet_nonce).await
        }
    }
}

/// Validates that the URL uses HTTPS scheme.
fn validate_https_scheme(uri: &Url) -> Result<(), RequestUriError> {
    // Allow HTTP for localhost in tests
    if uri.scheme() == "http" && is_localhost(uri) {
        return Ok(());
    }
    if uri.scheme() != "https" {
        return Err(RequestUriError::InvalidScheme);
    }
    Ok(())
}

/// Check if the URL is for a localhost/loopback address (for testing).
fn is_localhost(uri: &Url) -> bool {
    let host = uri.host_str().unwrap_or("");
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
}

/// Handles the HTTP response, validating status code and content type.
///
/// Returns the JWT string on success (HTTP 200 with correct content type).
/// Returns `AuthorizationError` variant if the Verifier returns an OAuth 2.0 error response.
async fn handle_response(
    response: reqwest::Response,
) -> Result<RequestUriResponse, RequestUriError> {
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

    // Handle non-success status codes
    if status != StatusCode::OK {
        // Try to parse as authorization error response
        if let Ok(auth_error) = serde_json::from_str::<AuthorizationErrorResponse>(&body) {
            return Ok(RequestUriResponse::Error(auth_error));
        }

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

    Ok(RequestUriResponse::Success(body.trim().to_string()))
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

    fn create_test_jwt() -> String {
        // A dummy JWT for testing (header.payload.signature)
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6Y2xpZW50LmV4YW1wbGUub3JnIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIn0.signature".to_string()
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_success() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();

        // Build HTTP response directly with proper content-type
        // Wiremock's ResponseTemplate sets text/plain for string bodies, so we use
        // a custom response transform
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
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_get_invalid_content_type() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/request"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(create_test_jwt()),
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
    async fn test_resolve_request_uri_get_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result = resolve_request_uri_get(&client, &uri).await;

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
        let jwt = create_test_jwt();
        let wallet_metadata = create_test_wallet_metadata();
        let wallet_nonce = "test-nonce-123";
        let client_id = "wallet.example.com";

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

        let result = resolve_request_uri_post(
            &client,
            &uri,
            client_id,
            Some(&wallet_metadata),
            Some(wallet_nonce),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_without_nonce() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();
        let wallet_metadata = create_test_wallet_metadata();
        let client_id = "wallet.example.com";

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
            resolve_request_uri_post(&client, &uri, client_id, Some(&wallet_metadata), None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_invalid_content_type() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let client_id = "wallet.example.com";

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "text/plain")
                    .set_body_string(create_test_jwt()),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result =
            resolve_request_uri_post(&client, &uri, client_id, Some(&wallet_metadata), None).await;

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
        let client_id = "wallet.example.com";

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result =
            resolve_request_uri_post(&client, &uri, client_id, Some(&wallet_metadata), None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::HttpError { status: 400, .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_authorization_error() {
        let mock_server = MockServer::start().await;
        let wallet_metadata = create_test_wallet_metadata();
        let client_id = "wallet.example.com";
        let error_response = json!({
            "error": "invalid_request",
            "error_description": "Missing required parameter"
        });

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Content-Type", "application/json")
                    .set_body_string(error_response.to_string()),
            )
            .mount(&mock_server)
            .await;

        let client = create_test_client();
        let uri = Url::parse(&format!("{}/request", mock_server.uri())).unwrap();

        let result =
            resolve_request_uri_post(&client, &uri, client_id, Some(&wallet_metadata), None).await;

        // Authorization errors are now returned as Ok(RequestUriResponse::Error)
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_invalid_scheme() {
        let client = create_test_client();
        let uri = Url::parse("http://example.com/request").unwrap();
        let wallet_metadata = create_test_wallet_metadata();
        let client_id = "wallet.example.com";

        let result =
            resolve_request_uri_post(&client, &uri, client_id, Some(&wallet_metadata), None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::InvalidScheme
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_dispatch_get() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();

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

        let result =
            resolve_request_uri(&client, &uri, RequestUriMethod::Get, None, None, None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_dispatch_post() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();
        let wallet_metadata = create_test_wallet_metadata();
        let client_id = "wallet.example.com";

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
            Some(client_id),
            Some(&wallet_metadata),
            None,
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_missing_client_id() {
        let client = create_test_client();
        let uri = Url::parse("https://example.com/request").unwrap();

        let result =
            resolve_request_uri(&client, &uri, RequestUriMethod::Post, None, None, None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RequestUriError::Serialization(_)
        ));
    }

    #[tokio::test]
    async fn test_resolve_request_uri_post_minimal_with_only_client_id() {
        // Per Section 5.10, only client_id is REQUIRED
        // wallet_metadata and wallet_nonce are OPTIONAL
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();
        let client_id = "wallet.example.com";

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

        // POST with only client_id (no wallet_metadata, no wallet_nonce)
        let result = resolve_request_uri_post(&client, &uri, client_id, None, None).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
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
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), body_content);
    }

    #[tokio::test]
    async fn test_content_type_with_charset() {
        let mock_server = MockServer::start().await;
        let jwt = create_test_jwt();

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
        let response = result.unwrap();
        assert!(response.is_success());
        assert_eq!(response.into_jwt().unwrap(), jwt);
    }

    #[test]
    fn test_request_uri_error_display() {
        let error = RequestUriError::InvalidScheme;
        assert!(error.to_string().contains("HTTPS"));

        let error = RequestUriError::InvalidContentType {
            expected: "expected-type".to_string(),
            actual: "actual-type".to_string(),
        };
        assert!(error.to_string().contains("expected-type"));
        assert!(error.to_string().contains("actual-type"));

        let error = RequestUriError::HttpError {
            status: 500,
            body: "error body".to_string(),
        };
        assert!(error.to_string().contains("500"));
        assert!(error.to_string().contains("error body"));
    }
}
