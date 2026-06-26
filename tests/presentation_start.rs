//! Integration tests for POST /api/v1/presentation/start

pub mod utils;

use cloud_identity_wallet::domain::models::credential::{
    Credential, CredentialDisplayMetadata, CredentialFormat, CredentialStatus,
};
use cloud_identity_wallet::domain::ports::CredentialRepo;
use cloud_wallet_openid4vc::oid4vci::metadata::CredentialDisplay;
use reqwest::{Client, StatusCode};
use serde_json::json;
use time::UtcDateTime;
use uuid::Uuid;

#[tokio::test]
async fn missing_authorization_returns_401() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .json(&json!({ "request": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_authorization_header_returns_401() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", "InvalidToken")
        .json(&json!({ "request": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_bearer_token_returns_401() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", "Bearer invalid_jwt_token")
        .json(&json!({ "request": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_request_with_valid_auth_returns_400() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "request": "" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_request");
}

#[tokio::test]
async fn missing_request_field_returns_422() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn valid_request_no_matching_credentials_returns_400() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let request = json!({
        "response_type": "vp_token",
        "client_id": "redirect_uri:https://verifier.example.com",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example.com/response",
        "nonce": "test-nonce",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "jwt_vc_json",
                "meta": { "type_values": [["VerifiableCredential", "EmployeeBadge"]] }
            }]
        }
    });

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "request": request.to_string() }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "no_matching_credentials");
}

#[tokio::test]
async fn valid_request_with_matching_credentials_returns_201() {
    let test_server = utils::spawn_server().await;
    let base_url = test_server.base_url;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer: "https://issuer.example".to_string(),
        subject: Some("did:example:alice".to_string()),
        credential_types: vec![
            "VerifiableCredential".to_string(),
            "EmployeeBadge".to_string(),
        ],
        format: CredentialFormat::JwtVcJson,
        external_id: Some("https://issuer.example/ext-123".to_string()),
        status: CredentialStatus::Active,
        issued_at: UtcDateTime::now(),
        valid_until: None,
        is_revoked: false,
        status_location: None,
        status_index: None,
        raw_credential: "header.eyJzdWIiOiJhbGljZSJ9.signature".to_string(),
    };

    let display = CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: "Employee Badge".to_string(),
            ..Default::default()
        },
        issuer_name: "Test Issuer".to_string(),
        credential_type: "EmployeeBadge".to_string(),
    };

    test_server
        .credential_repo
        .upsert(credential, Some(display))
        .await
        .expect("Failed to insert credential");

    let request = json!({
        "response_type": "vp_token",
        "client_id": "redirect_uri:https://verifier.example.com",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example.com/response",
        "nonce": "test-nonce",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "jwt_vc_json",
                "meta": { "type_values": [["VerifiableCredential", "EmployeeBadge"]] }
            }]
        }
    });

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "request": request.to_string() }))
        .send()
        .await
        .expect("Failed to send request");

    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(status, StatusCode::CREATED, "response body: {body}");
    let session_id = body.get("session_id").unwrap().as_str().unwrap();
    assert!(session_id.starts_with("prs_"));

    let flow = body.get("flow").unwrap().as_str().unwrap();
    assert_eq!(flow, "cross_device");

    let verifier = body.get("verifier").unwrap();
    assert_eq!(
        verifier.get("name").unwrap(),
        "https://verifier.example.com"
    );
    assert_eq!(verifier.get("verified").unwrap(), false);
    assert!(verifier.get("verification_method").unwrap().is_null());

    let credential_matches = body.get("credential_matches").unwrap().as_array().unwrap();
    assert_eq!(credential_matches.len(), 1);
    let match_info = &credential_matches[0];
    assert_eq!(match_info.get("query_id").unwrap(), "pid");
    assert_eq!(match_info.get("required").unwrap(), true);

    let candidates = match_info.get("candidates").unwrap().as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    let display = candidate.get("display").unwrap();
    assert_eq!(display.get("name").unwrap(), "Employee Badge");
    assert_eq!(display.get("issuer_name").unwrap(), "Test Issuer");
    assert_eq!(display.get("credential_type").unwrap(), "EmployeeBadge");

    assert_eq!(body.get("requires_consent").unwrap(), true);
    assert!(body.get("transaction_data").unwrap().is_null());
}

#[tokio::test]
async fn fragment_response_mode_returns_same_device_flow() {
    let test_server = utils::spawn_server().await;
    let base_url = test_server.base_url;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer: "https://issuer.example".to_string(),
        subject: Some("did:example:alice".to_string()),
        credential_types: vec![
            "VerifiableCredential".to_string(),
            "EmployeeBadge".to_string(),
        ],
        format: CredentialFormat::JwtVcJson,
        external_id: Some("https://issuer.example/ext-123".to_string()),
        status: CredentialStatus::Active,
        issued_at: UtcDateTime::now(),
        valid_until: None,
        is_revoked: false,
        status_location: None,
        status_index: None,
        raw_credential: "header.eyJzdWIiOiJhbGljZSJ9.signature".to_string(),
    };

    let display = CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: "Employee Badge".to_string(),
            ..Default::default()
        },
        issuer_name: "Test Issuer".to_string(),
        credential_type: "EmployeeBadge".to_string(),
    };

    test_server
        .credential_repo
        .upsert(credential, Some(display))
        .await
        .expect("Failed to insert credential");

    let request = json!({
        "response_type": "vp_token",
        "client_id": "redirect_uri:https://verifier.example.com",
        "response_mode": "fragment",
        "redirect_uri": "https://verifier.example.com/callback",
        "nonce": "test-nonce",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "jwt_vc_json",
                "meta": { "type_values": [["VerifiableCredential", "EmployeeBadge"]] }
            }]
        }
    });

    let response = client
        .post(format!("{}/api/v1/presentation/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "request": request.to_string() }))
        .send()
        .await
        .expect("Failed to send request");

    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(status, StatusCode::CREATED, "response body: {body}");
    let flow = body.get("flow").unwrap().as_str().unwrap();
    assert_eq!(flow, "same_device");
}
