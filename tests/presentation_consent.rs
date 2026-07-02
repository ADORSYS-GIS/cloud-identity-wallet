//! Integration tests for POST /api/v1/presentation/{session_id}/consent

pub mod utils;

use reqwest::{Client, StatusCode};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn consent_on_nonexistent_session_returns_404() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let response = client
        .post(format!(
            "{}/api/v1/presentation/prs_nonexistent/consent",
            base_url
        ))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "accepted": true, "selected_credentials": [] }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "session_not_found");
}

#[tokio::test]
async fn consent_without_auth_returns_401() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/presentation/prs_test/consent", base_url))
        .json(&json!({ "accepted": false }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn consent_malformed_json_returns_400() {
    let base_url = utils::spawn_server().await.base_url;
    let client = Client::new();
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let response = client
        .post(format!("{}/api/v1/presentation/prs_test/consent", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body("{invalid json")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_request");
}
