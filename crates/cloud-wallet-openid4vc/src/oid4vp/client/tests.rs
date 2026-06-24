use super::*;
use crate::oauth::authorization::OAuthAuthorizationRequest;
use crate::oid4vp::authorization::ResponseType;
use crate::oid4vp::dcql::{CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Creates a minimal valid `AuthorizationRequest` for testing.
fn test_authorization_request() -> AuthorizationRequest {
    AuthorizationRequest {
        response_type: ResponseType::VpToken,
        oauth: OAuthAuthorizationRequest {
            client_id: "redirect_uri:https://verifier.example.com/cb".into(),
            redirect_uri: None,
            scope: None,
            state: Some("test-state".into()),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
        },
        nonce: "test-nonce".into(),
        response_mode: ResponseMode::DirectPost,
        response_uri: Some(Url::parse("https://verifier.example.com/response").unwrap()),
        request_uri: None,
        request_uri_method: None,
        dcql_query: Some(test_dcql_query()),
        client_metadata: None,
        client_metadata_uri: None,
        request: None,
        transaction_data: None,
        verifier_info: None,
        expected_origins: None,
    }
}

fn test_dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: "pid_request".into(),
            format: CredentialFormat::DcSdJwt,
            multiple: None,
            meta: CredentialMeta::SdJwt {
                vct_values: vec!["https://example.com/pid".into()],
            },
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        }],
        credential_sets: None,
    }
}

fn test_config() -> Oid4vpConfig {
    let inner = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("valid client");
    Oid4vpConfig {
        http_client: reqwest_middleware::ClientBuilder::new(inner).build(),
        discovery_mode: DiscoveryMode::Static,
        wallet_metadata: None,
    }
}

fn signed_request_object(client_id: &str, wallet_nonce: Option<&str>) -> String {
    let now = jsonwebtoken::get_current_timestamp() as i64;
    let mut payload = serde_json::json!({
        "iss": client_id,
        "aud": "https://self-issued.me/v2",
        "exp": now + 300,
        "iat": now,
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": "test-nonce",
        "response_uri": "https://verifier.example.com/response",
        "dcql_query": {
            "credentials": [{
                "id": "pid_request",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com/pid"] }
            }]
        }
    });
    if let Some(wallet_nonce) = wallet_nonce {
        payload["wallet_nonce"] = serde_json::Value::String(wallet_nonce.to_string());
    }

    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some("oauth-authz-req+jwt".to_string());
    encode(&header, &payload, &EncodingKey::from_secret(b"test-secret"))
        .expect("test JWT should encode")
}

struct StaticKeyResolver;

#[async_trait::async_trait]
impl VerifierKeyResolver for StaticKeyResolver {
    async fn resolve_key(
        &self,
        _client_id: &ParsedClientId,
        _header: &Header,
    ) -> crate::errors::Result<DecodingKey> {
        Ok(DecodingKey::from_secret(b"test-secret"))
    }
}

struct StaticRequestUriResolver {
    result: RequestUriResult,
    saw_post: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl RequestUriResolver for StaticRequestUriResolver {
    async fn resolve(
        &self,
        _http_client: &ClientWithMiddleware,
        _uri: &Url,
        method: Option<RequestUriMethod>,
        _wallet_metadata: Option<&WalletPresentationMetadata>,
    ) -> Result<RequestUriResult, RequestUriError> {
        self.saw_post.store(
            matches!(method, Some(RequestUriMethod::Post)),
            Ordering::SeqCst,
        );
        Ok(self.result.clone())
    }
}

struct RejectingVerifierResolver;

#[async_trait::async_trait]
impl VerifierKeyResolver for RejectingVerifierResolver {
    async fn resolve_key(
        &self,
        _client_id: &ParsedClientId,
        _header: &Header,
    ) -> crate::errors::Result<DecodingKey> {
        Ok(DecodingKey::from_secret(b"test-secret"))
    }
}

#[async_trait::async_trait]
impl VerifierResolver for RejectingVerifierResolver {
    async fn resolve_metadata(
        &self,
        client_id: &ParsedClientId,
        _request: &AuthorizationRequest,
    ) -> Result<Option<VerifierMetadata>, Error> {
        Err(Error::VerifierResolutionFailed(format!(
            "unsupported client_id scheme: {:?}",
            client_id.prefix()
        )))
    }
}

#[test]
fn presentation_context_credential_queries() {
    let request = test_authorization_request();
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    assert_eq!(ctx.credential_queries().len(), 1);
    assert_eq!(ctx.credential_queries()[0].id, "pid_request");
}

#[test]
fn presentation_context_has_no_transaction_data() {
    let request = test_authorization_request();
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    assert!(!ctx.has_transaction_data());
}

#[test]
fn presentation_context_require_response_uri_absent() {
    let mut request = test_authorization_request();
    request.response_uri = None;
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: None,
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    assert!(matches!(
        ctx.require_response_uri(),
        Err(Error::NoResponseUri)
    ));
}

#[test]
fn parse_json_authorization_request() {
    let client = Oid4vpClient::new(test_config());
    let json = serde_json::to_string(&test_authorization_request()).unwrap();
    let result = client.parse_authorization_request(&json);
    assert!(result.is_ok(), "parse failed: {:?}", result.err());
    let request = result.unwrap();
    assert_eq!(request.nonce, "test-nonce");
}

#[test]
fn parse_empty_request_fails() {
    let client = Oid4vpClient::new(test_config());
    let result = client.parse_authorization_request("");
    assert!(matches!(result, Err(Error::InvalidRequest(_))));
}

#[test]
fn parse_invalid_json_fails() {
    let client = Oid4vpClient::new(test_config());
    let result = client.parse_authorization_request("{not valid json");
    assert!(matches!(result, Err(Error::InvalidRequest(_))));
}

#[tokio::test]
async fn process_request_uri_accepts_partial_outer_request() {
    let client = Oid4vpClient::new(test_config());
    let saw_post = Arc::new(AtomicBool::new(false));
    let resolver = StaticRequestUriResolver {
        result: RequestUriResult::new(
            signed_request_object("x509_san_dns:verifier.example.com", None),
            None,
        ),
        saw_post: Arc::clone(&saw_post),
    };
    let raw = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2Fabc123&request_uri_method=post&client_id=x509_san_dns%3Averifier.example.com";

    let context = client
        .process_authz_request_full(raw, &StaticKeyResolver, None, &resolver)
        .await
        .expect("partial request_uri envelope should resolve to a validated request object");

    assert!(saw_post.load(Ordering::SeqCst));
    assert_eq!(context.client_id.value(), "verifier.example.com");
    assert_eq!(context.credential_queries()[0].id, "pid_request");
}

#[tokio::test]
async fn process_request_uri_validates_wallet_nonce_after_request_object_decode() {
    let client = Oid4vpClient::new(test_config());
    let resolver = StaticRequestUriResolver {
        result: RequestUriResult::new(
            signed_request_object("x509_san_dns:verifier.example.com", Some("actual")),
            Some("expected".to_string()),
        ),
        saw_post: Arc::new(AtomicBool::new(false)),
    };
    let raw = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2Fabc123&client_id=x509_san_dns%3Averifier.example.com";

    let err = client
        .process_authz_request_full(raw, &StaticKeyResolver, None, &resolver)
        .await
        .expect_err("wallet_nonce mismatch must fail");

    assert!(matches!(
        err,
        Error::InvalidRequestObject(RequestObjectError::InvalidClaims(_))
    ));
}

#[tokio::test]
async fn process_authorization_request_delegates_verifier_resolution_to_handler() {
    let client = Oid4vpClient::new(test_config());
    let json = serde_json::to_string(&test_authorization_request()).unwrap();

    let err = client
        .process_authz_request_with_resolver(&json, &RejectingVerifierResolver)
        .await
        .expect_err("verifier resolver errors should surface");

    assert!(matches!(err, Error::VerifierResolutionFailed(_)));
}

#[test]
fn client_new() {
    let config = test_config();
    let client = Oid4vpClient::new(config);
    assert_eq!(client.config().discovery_mode, DiscoveryMode::Static);
}

#[test]
fn error_no_response_uri_display() {
    let err = Error::NoResponseUri;
    assert!(err.to_string().contains("no response_uri"));
}

#[test]
fn error_invalid_request_display() {
    let err = Error::InvalidRequest("test error".into());
    assert!(err.to_string().contains("test error"));
}

#[test]
fn error_response_builds_with_state() {
    let request = test_authorization_request();
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    let response = AuthorizationResponse::error(AuthorizationErrorCode::AccessDenied);
    let response = response.with_state(ctx.state.as_deref().unwrap_or(""));
    assert!(matches!(response, AuthorizationResponse::Error(_)));
}

#[tokio::test]
async fn create_error_response_returns_unsupported_mode() {
    let mut request = test_authorization_request();
    request.response_mode = ResponseMode::DirectPostJwt;
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    let client = Oid4vpClient::new(test_config());
    let result = client
        .create_error_response(&ctx, AuthorizationErrorCode::AccessDenied)
        .await;
    assert!(
        matches!(result, Err(Error::UnsupportedResponseMode(_))),
        "direct_post.jwt without encryption sender should return UnsupportedResponseMode"
    );
}

#[tokio::test]
async fn create_error_response_rejects_dc_api_mode() {
    let mut request = test_authorization_request();
    request.response_mode = ResponseMode::DcApi;
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    let client = Oid4vpClient::new(test_config());
    let result = client
        .create_error_response(&ctx, AuthorizationErrorCode::AccessDenied)
        .await;
    assert!(
        matches!(result, Err(Error::UnsupportedResponseMode(_))),
        "dc_api response mode should return UnsupportedResponseMode"
    );
}

#[tokio::test]
async fn create_error_response_rejects_dc_api_jwt_mode() {
    let mut request = test_authorization_request();
    request.response_mode = ResponseMode::DcApiJwt;
    let dcql_query = request.dcql_query.clone().unwrap();
    let ctx = PresentationContext {
        nonce: request.nonce.clone(),
        state: request.oauth.state.clone(),
        response_uri: request.response_uri.clone(),
        response_mode: request.response_mode.clone(),
        dcql_query,
        transaction_data: vec![],
        verifier_metadata: None,
        client_id: ParsedClientId::parse(&request.oauth.client_id).unwrap(),
        request,
    };

    let client = Oid4vpClient::new(test_config());
    let result = client
        .create_error_response(&ctx, AuthorizationErrorCode::AccessDenied)
        .await;
    assert!(
        matches!(result, Err(Error::UnsupportedResponseMode(_))),
        "dc_api.jwt response mode should return UnsupportedResponseMode"
    );
}

#[tokio::test]
async fn process_inline_request_jwt() {
    let client = Oid4vpClient::new(test_config());
    let jwt = signed_request_object("redirect_uri:https://verifier.example.com/cb", None);

    let raw = serde_json::json!({
        "response_type": "vp_token",
        "client_id": "redirect_uri:https://verifier.example.com/cb",
        "nonce": "test-nonce",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example.com/response",
        "dcql_query": {
            "credentials": [{
                "id": "pid_request",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com/pid"] }
            }]
        },
        "request": jwt
    });

    let context = client
        .process_authz_request(&raw.to_string(), &StaticKeyResolver)
        .await
        .expect("inline request JWT should resolve to a validated request object");

    assert_eq!(context.nonce, "test-nonce");
    assert_eq!(context.credential_queries()[0].id, "pid_request");
}

#[tokio::test]
async fn rejects_unsigned_request_for_non_redirect_uri_prefix() {
    let client = Oid4vpClient::new(test_config());
    // x509_san_dns prefix requires a signed Request Object per OpenID4VP §5.9.3.
    // An unsigned request with this prefix must be rejected.
    let raw = "openid4vp://?response_type=vp_token&client_id=x509_san_dns%3Averifier.example.com&nonce=test-nonce&response_mode=direct_post&response_uri=https%3A%2F%2Fverifier.example.com%2Fresponse&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22pid%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22https%3A%2F%2Fexample.com%2Fpid%22%5D%7D%7D%5D%7D";

    let err = client
        .process_authz_request(raw, &StaticKeyResolver)
        .await
        .expect_err("unsigned request with x509_san_dns prefix should be rejected");

    match &err {
        Error::InvalidRequest(msg) => {
            assert!(
                msg.contains("unsigned"),
                "expected unsigned rejection, got: {msg}"
            );
            assert!(
                msg.contains("x509_san_dns"),
                "expected prefix in error, got: {msg}"
            );
        }
        other => panic!("expected InvalidRequest, got: {other:?}"),
    }
}

#[tokio::test]
async fn create_response_path_end_to_end() {
    use crate::oid4vp::presentation::SelectedCredential;
    use crate::oid4vp::selection::CredentialView;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let mock_uri = format!("{}/response", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/response"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("vp_token="))
        .and(body_string_contains("state=test-state"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"redirect_uri": "https://verifier.example.com/cb"}),
            ),
        )
        .mount(&mock_server)
        .await;

    let now = jsonwebtoken::get_current_timestamp() as i64;
    let payload = serde_json::json!({
        "iss": "redirect_uri:https://verifier.example.com/cb",
        "aud": "https://self-issued.me/v2",
        "exp": now + 300,
        "iat": now,
        "client_id": "redirect_uri:https://verifier.example.com/cb",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": "test-nonce",
        "state": "test-state",
        "response_uri": mock_uri,
        "dcql_query": {
            "credentials": [{
                "id": "pid_request",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://example.com/pid"] }
            }]
        }
    });

    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.typ = Some("oauth-authz-req+jwt".to_string());
    let jwt = encode(
        &jwt_header,
        &payload,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("test JWT should encode");

    let raw = serde_json::json!({
        "response_type": "vp_token",
        "client_id": "redirect_uri:https://verifier.example.com/cb",
        "request": jwt
    });

    let client = Oid4vpClient::new(test_config());

    let resolver = StaticRequestUriResolver {
        result: RequestUriResult::new(String::new(), None),
        saw_post: Arc::new(AtomicBool::new(false)),
    };

    let context = client
        .process_authz_request_full(&raw.to_string(), &StaticKeyResolver, None, &resolver)
        .await
        .expect("request should be valid");

    let my_cred = CredentialView {
        id: "my-pid-1".into(),
        format: CredentialFormat::DcSdJwt,
        vct: Some("https://example.com/pid".into()),
        doctype: None,
        credential_types: vec![],
        claims: serde_json::json!({"given_name": "Alice"}),
        holder_binding_supported: true,
        issuer: Some("did:example:issuer".into()),
        trusted_authorities: vec![],
    };
    let selection = client.match_credentials(&context, &[my_cred]);
    assert!(selection.satisfies_query);

    let selected = vec![SelectedCredential::string(
        "pid_request",
        "eyJhbGciOiJFUzI1NiJ9.mock-vp-token",
    )];

    let response = client
        .create_response(&context, selected)
        .await
        .expect("create_response should succeed");

    assert_eq!(
        response.redirect_uri,
        Some(url::Url::parse("https://verifier.example.com/cb").unwrap())
    );
}

#[test]
fn parse_haip_vp_uri() {
    // Test haip-vp:// scheme (HAIP §5.1) - should be accepted
    // Using request_uri to avoid DCQL JSON encoding complexity in URL
    let client = Oid4vpClient::new(test_config());
    let haip_uri = "haip-vp://?response_type=vp_token&client_id=test-verifier&nonce=abc123&response_mode=direct_post&response_uri=https%3A%2F%2Fverifier.example.com%2Fresponse&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest";

    // This should parse successfully at the URI level
    let result = client.parse_authorization_request_envelope(haip_uri);
    assert!(
        result.is_ok(),
        "haip-vp:// URI should parse envelope: {:?}",
        result.err()
    );
    let envelope = result.unwrap();
    assert_eq!(envelope.client_id, "test-verifier");
    assert!(envelope.request_uri.is_some());
}

#[test]
fn parse_openid4vp_uri_envelope() {
    // Test openid4vp:// scheme - should be accepted
    // Using request_uri to avoid DCQL JSON encoding complexity in URL
    let client = Oid4vpClient::new(test_config());
    let openid4vp_uri = "openid4vp://?response_type=vp_token&client_id=test-verifier&nonce=xyz789&response_mode=direct_post&response_uri=https%3A%2F%2Fverifier.example.com%2Fresponse&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest";

    let result = client.parse_authorization_request_envelope(openid4vp_uri);
    assert!(
        result.is_ok(),
        "openid4vp:// URI should parse envelope: {:?}",
        result.err()
    );
    let envelope = result.unwrap();
    assert_eq!(envelope.client_id, "test-verifier");
    assert!(envelope.request_uri.is_some());
}

#[test]
fn parse_uri_rejects_unsupported_scheme_for_oid4vp() {
    // Unsupported schemes like haip-vci:// should be rejected for OID4VP
    let client = Oid4vpClient::new(test_config());

    let haip_vci_uri = "haip-vci://?client_id=test&nonce=abc";
    let result = client.parse_authorization_request_envelope(haip_vci_uri);
    assert!(result.is_err(), "haip-vci:// URI should fail for OID4VP");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("failed to parse"),
        "Expected parse error for unsupported scheme: {}",
        err
    );
}

#[test]
fn parse_uri_case_insensitive_scheme() {
    // Scheme should be case-insensitive
    let client = Oid4vpClient::new(test_config());

    let uppercase = "HAIP-VP://?response_type=vp_token&client_id=test&nonce=abc&response_mode=direct_post&response_uri=https%3A%2F%2Fexample.com&request_uri=https%3A%2F%2Fexample.com%2Frequest";
    let result = client.parse_authorization_request_envelope(uppercase);
    assert!(
        result.is_ok(),
        "HAIP-VP:// should parse: {:?}",
        result.err()
    );

    let mixed = "OpenId4Vp://?response_type=vp_token&client_id=test&nonce=abc&response_mode=direct_post&response_uri=https%3A%2F%2Fexample.com&request_uri=https%3A%2F%2Fexample.com%2Frequest";
    let result = client.parse_authorization_request_envelope(mixed);
    assert!(
        result.is_ok(),
        "OpenId4Vp:// should parse: {:?}",
        result.err()
    );
}
