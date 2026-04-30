//! Integration tests for POST /api/v1/tenants

mod utils;

use axum::http::header;

#[tokio::test]
async fn valid_name_returns_201() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": "Acme Corporation" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body.get("tenant_id").is_some());
    assert_eq!(body.get("name").unwrap(), "Acme Corporation");

    // Verify tenant_id is a valid UUID
    let tenant_id = body.get("tenant_id").unwrap().as_str().unwrap();
    assert!(uuid::Uuid::parse_str(tenant_id).is_ok());
}

#[tokio::test]
async fn empty_name_returns_400() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": "" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_request");
}

#[tokio::test]
async fn whitespace_only_name_returns_400() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": "   " }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_request");
}

#[tokio::test]
async fn name_256_chars_returns_400() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let long_name = "a".repeat(256);

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": long_name }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_request");
}

#[tokio::test]
async fn name_255_chars_returns_201() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let max_name = "a".repeat(255);

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": max_name }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(body.get("tenant_id").is_some());
}

#[tokio::test]
async fn duplicate_names_produce_distinct_ids() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let name = "Same Name Inc.";

    // First registration
    let response1 = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .expect("Failed to send request");

    let body1: serde_json::Value = response1.json().await.expect("Failed to parse response");
    let id1 = body1.get("tenant_id").unwrap().as_str().unwrap();

    // Second registration with same name
    let response2 = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .expect("Failed to send request");

    let body2: serde_json::Value = response2.json().await.expect("Failed to parse response");
    let id2 = body2.get("tenant_id").unwrap().as_str().unwrap();

    // IDs should be different
    assert_ne!(id1, id2);
}

#[tokio::test]
async fn name_is_trimmed_in_response() {
    let base_url = utils::spawn_server().await;
    let (client, auth_header, _) = utils::create_authenticated_client_and_token().await;

    let response = client
        .post(format!("{}/api/v1/tenants", base_url))
        .header(header::AUTHORIZATION, &auth_header)
        .json(&serde_json::json!({ "name": "  Trimmed Name  " }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 201);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("name").unwrap(), "Trimmed Name");
}
