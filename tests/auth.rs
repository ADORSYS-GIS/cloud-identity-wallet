mod utils;

use cloud_identity_wallet::server::generate_token;
use reqwest::Client;
use uuid::Uuid;

#[tokio::test]
async fn test_protected_endpoint_requires_auth() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .get(format!("{addr}/api/v1/protected"))
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(reqwest::StatusCode::UNAUTHORIZED, response.status());

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["error"], "unauthorized");
    assert_eq!(
        body["error_description"],
        "Missing or invalid bearer token."
    );
}

#[tokio::test]
async fn test_protected_endpoint_with_valid_token() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let secret = "development-secret-change-in-production";
    let token = generate_token(tenant_id, secret, 3600).expect("Failed to generate token");

    let response = client
        .get(format!("{addr}/api/v1/protected"))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(response.status().is_success());
}

#[tokio::test]
async fn test_protected_endpoint_with_invalid_token() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .get(format!("{addr}/api/v1/protected"))
        .bearer_auth("invalid-token")
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(reqwest::StatusCode::UNAUTHORIZED, response.status());

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["error"], "unauthorized");
    assert_eq!(
        body["error_description"],
        "Missing or invalid bearer token."
    );
}

#[tokio::test]
async fn test_protected_endpoint_with_wrong_secret() {
    let addr = utils::spawn_server().await;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let wrong_secret = "wrong-secret";
    let token = generate_token(tenant_id, wrong_secret, 3600).expect("Failed to generate token");

    let response = client
        .get(format!("{addr}/api/v1/protected"))
        .bearer_auth(token)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(reqwest::StatusCode::UNAUTHORIZED, response.status());
}
