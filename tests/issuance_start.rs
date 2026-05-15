//! Integration tests for POST /api/v1/issuance/start

pub mod utils;

use reqwest::{Client, StatusCode};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn missing_authorization_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_authorization_header_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", "InvalidToken")
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_bearer_token_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", "Bearer invalid_jwt_token")
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_offer_with_valid_auth_returns_400() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (encoding_key, public_jwk) = utils::create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_token_with_keypair(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "offer": "" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_credential_offer");
}

#[tokio::test]
async fn missing_offer_field_returns_422() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (encoding_key, public_jwk) = utils::create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_token_with_keypair(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn invalid_offer_uri_returns_internal_error() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (encoding_key, public_jwk) = utils::create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_token_with_keypair(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "offer": "openid-credential-offer://?credential_offer_uri=https://nonexistent.invalid/offer.json"
        }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
