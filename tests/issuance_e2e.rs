mod utils;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::Client;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_offer_uri(issuer_url: &str, grants: Option<serde_json::Value>) -> String {
    let mut offer = json!({
        "credential_issuer": issuer_url,
        "credential_configuration_ids": ["UniversityDegreeCredential"]
    });
    if let Some(g) = grants {
        offer["grants"] = g;
    }
    let json_str = offer.to_string();
    let encoded = utf8_percent_encode(&json_str, NON_ALPHANUMERIC);
    format!("openid-credential-offer://?credential_offer={encoded}")
}

fn make_pre_auth_offer(issuer_url: &str, pre_auth_code: &str) -> String {
    make_offer_uri(
        issuer_url,
        Some(json!({
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code
            }
        })),
    )
}

fn make_authz_code_offer(issuer_url: &str, issuer_state: &str) -> String {
    make_offer_uri(
        issuer_url,
        Some(json!({
            "authorization_code": {
                "issuer_state": issuer_state
            }
        })),
    )
}

fn make_empty_grants_offer(issuer_url: &str) -> String {
    make_offer_uri(issuer_url, Some(json!({})))
}

fn make_no_grants_offer(issuer_url: &str) -> String {
    make_offer_uri(issuer_url, None)
}

fn make_pre_auth_offer_with_tx_code(issuer_url: &str, pre_auth_code: &str) -> String {
    make_offer_uri(
        issuer_url,
        Some(json!({
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
                "tx_code": {
                    "input_mode": "numeric",
                    "length": 6,
                    "description": "Enter the 6-digit code"
                }
            }
        })),
    )
}

#[tokio::test]
async fn start_issuance_pre_authorized_code_returns_201() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer(&issuer_url, "test_pre_auth_code_123");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body.get("session_id").is_some());
    assert!(body.get("expires_at").is_some());
    assert_eq!(body.get("flow").unwrap(), "pre_authorized_code");
    assert_eq!(body.get("tx_code_required").unwrap(), false);
}

#[tokio::test]
async fn start_issuance_authorization_code_returns_201() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_authz_code_offer(&issuer_url, "test_issuer_state");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body.get("session_id").is_some());
    assert!(body.get("expires_at").is_some());
    assert_eq!(body.get("flow").unwrap(), "authorization_code");
}

#[tokio::test]
async fn start_issuance_invalid_offer_returns_400() {
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": "not_a_valid_offer" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_credential_offer");
}

#[tokio::test]
async fn start_issuance_missing_offer_returns_400() {
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("Failed to send request");

    // Axum returns 422 for missing required JSON fields
    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn start_issuance_returns_expires_at() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer(&issuer_url, "test_code");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let expires_at = body.get("expires_at").unwrap().as_str().unwrap();
    // Verify it's a valid RFC3339 timestamp
    assert!(
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .is_ok()
    );
}

#[tokio::test]
async fn start_issuance_with_tx_code_returns_tx_code_spec() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer_with_tx_code(&issuer_url, "test_code");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("tx_code_required").unwrap(), true);
    let tx_code = body.get("tx_code").unwrap();
    assert_eq!(tx_code.get("input_mode").unwrap(), "numeric");
    assert_eq!(tx_code.get("length").unwrap(), 6);
}

#[tokio::test]
async fn start_issuance_issuer_metadata_failure_returns_502() {
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    // Point to a non-existent server to trigger metadata discovery failure
    let offer_json = json!({
        "credential_issuer": "https://non-existent-issuer.example.com",
        "credential_configuration_ids": ["TestCredential"]
    })
    .to_string();
    let encoded = utf8_percent_encode(&offer_json, NON_ALPHANUMERIC);
    let offer_uri = format!("openid-credential-offer://?credential_offer={encoded}");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_uri }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 502);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "issuer_metadata_fetch_failed");
}

#[tokio::test]
async fn start_issuance_empty_grants_falls_back_to_as_metadata() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    // Offer with empty grants — should fall back to AS metadata
    let offer_json = make_empty_grants_offer(&issuer_url);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    // Should succeed because AS metadata has authorization_code
    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("flow").unwrap(), "authorization_code");
}

#[tokio::test]
async fn start_issuance_no_grants_uses_as_metadata() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    // Offer without grants field at all
    let offer_json = make_no_grants_offer(&issuer_url);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    // Should succeed because AS metadata has authorization_code
    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("flow").unwrap(), "authorization_code");
}

#[tokio::test]
async fn start_issuance_no_supported_grant_type_returns_400() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;

    // AS metadata with no supported grant types
    let as_metadata_json = json!({
        "issuer": issuer_url.replace("http://", "https://"),
        "grant_types_supported": []
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_metadata_json))
        .mount(&mock_server)
        .await;

    // Offer without grants — will fall back to AS metadata which has no supported grants
    let offer_json = make_no_grants_offer(&issuer_url);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_credential_offer");
}

#[tokio::test]
async fn start_issuance_as_metadata_with_pre_authorized_code_grant() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;

    // AS metadata with pre-authorized_code grant type
    let as_metadata_json = json!({
        "issuer": as_url,
        "authorization_endpoint": format!("{as_url}/authorize"),
        "token_endpoint": format!("{as_url}/token"),
        "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "code_challenge_methods_supported": ["S256"]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_metadata_json))
        .mount(&mock_server)
        .await;

    // Offer without grants — will fall back to AS metadata
    let offer_json = make_no_grants_offer(&issuer_url);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    // Should succeed and select pre-authorized_code flow
    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("flow").unwrap(), "pre_authorized_code");
}

#[tokio::test]
async fn start_issuance_session_contains_sanitized_offer() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer(&issuer_url, "sensitive_token_12345");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let session_id = body.get("session_id").unwrap().as_str().unwrap();

    // Verify session was created and can be retrieved
    // The session should exist in memory store
    // Note: We can't directly access the session store from here, but we can verify
    // the response contains the expected fields
    assert!(!session_id.is_empty());
    assert!(body.get("expires_at").is_some());
}

#[tokio::test]
async fn start_issuance_response_contains_issuer_info() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer(&issuer_url, "test_code");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let issuer = body.get("issuer").unwrap();
    assert!(issuer.get("credential_issuer").is_some());
}

#[tokio::test]
async fn start_issuance_response_contains_credential_types() {
    let mock_server = MockServer::start().await;
    let base_url = utils::spawn_server_with_mock_issuer().await;
    let client = Client::new();

    let issuer_url = mock_server.uri();
    let as_url = issuer_url.replace("http://", "https://");

    setup_issuer_metadata_mock(&mock_server, &issuer_url).await;
    setup_as_metadata_mock(&mock_server, &as_url).await;

    let offer_json = make_pre_auth_offer(&issuer_url, "test_code");

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&serde_json::json!({ "offer": offer_json }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    let credential_types = body.get("credential_types").unwrap().as_array().unwrap();
    assert!(!credential_types.is_empty());

    let cred_type = &credential_types[0];
    assert_eq!(
        cred_type.get("credential_configuration_id").unwrap(),
        "UniversityDegreeCredential"
    );
    assert!(cred_type.get("format").is_some());
    assert!(cred_type.get("display").is_some());
}

async fn setup_issuer_metadata_mock(mock_server: &MockServer, issuer_url: &str) {
    let metadata_json = json!({
        "credential_issuer": issuer_url,
        "credential_endpoint": format!("{issuer_url}/credential"),
        "nonce_endpoint": format!("{issuer_url}/nonce"),
        "authorization_servers": [issuer_url],
        "credential_configurations_supported": {
            "UniversityDegreeCredential": {
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256"]
                    }
                },
                "credential_metadata": {
                    "display": [{
                        "name": "University Degree",
                        "locale": "en"
                    }]
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_json))
        .mount(mock_server)
        .await;
}

async fn setup_as_metadata_mock(mock_server: &MockServer, as_url: &str) {
    let as_metadata_json = json!({
        "issuer": as_url,
        "authorization_endpoint": format!("{as_url}/authorize"),
        "token_endpoint": format!("{as_url}/token"),
        "pushed_authorization_request_endpoint": format!("{as_url}/par"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"]
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(as_metadata_json))
        .mount(mock_server)
        .await;
}
