//! Integration tests for DELETE /api/v1/credentials/{id}

pub mod utils;

use std::sync::Arc;

use reqwest::{Client, StatusCode};
use uuid::Uuid;

use cloud_identity_wallet::{
    domain::ports::CredentialRepo, outbound::MemoryTenantRepo, server::Server,
    session::MemorySession, setup,
};

/// Spawns a test server and returns the base URL and the shared credential
/// repository for direct seeding. The server task runs until the runtime
/// shuts down at the end of each test.
async fn spawn_server_with_repo() -> (String, Arc<dyn CredentialRepo>) {
    let config = utils::make_config();
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();
    let service = setup::build_service(session_store, tenant_repo, &config).unwrap();
    let credential_repo = Arc::clone(&service.issuance_engine.credential_repo);
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();
    tokio::spawn(server.run());
    (
        format!("http://{}:{}", config.server.host, port),
        credential_repo,
    )
}

#[tokio::test]
async fn delete_missing_auth_returns_401() {
    // Arrange
    let (base_url, _) = spawn_server_with_repo().await;
    let client = Client::new();
    let id = Uuid::new_v4();

    // Act
    let response = client
        .delete(format!("{base_url}/api/v1/credentials/{id}"))
        .send()
        .await
        .expect("Failed to send request");

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_owned_credential_returns_204() {
    // Arrange
    let (base_url, repo) = spawn_server_with_repo().await;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = utils::sample_credential(tenant_id);
    let credential_id = credential.id;
    repo.upsert(credential)
        .await
        .expect("Failed to seed credential");

    // Act
    let response = client
        .delete(format!("{base_url}/api/v1/credentials/{credential_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_is_idempotent_second_call_returns_404() {
    // Arrange
    let (base_url, repo) = spawn_server_with_repo().await;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = utils::sample_credential(tenant_id);
    let credential_id = credential.id;
    repo.upsert(credential)
        .await
        .expect("Failed to seed credential");

    // Act — first delete succeeds
    let first = client
        .delete(format!("{base_url}/api/v1/credentials/{credential_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send first request");
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    // Act — second delete on same credential returns 404
    let second = client
        .delete(format!("{base_url}/api/v1/credentials/{credential_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send second request");

    // Assert
    assert_eq!(second.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = second.json().await.expect("Failed to parse response");
    assert_eq!(body["error"], "credential_not_found");
}

#[tokio::test]
async fn delete_another_tenants_credential_returns_404() {
    // Arrange — two tenants share the same server instance
    let (base_url, repo) = spawn_server_with_repo().await;
    let client = Client::new();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Seed a credential owned by tenant A
    let credential_a = utils::sample_credential(tenant_a);
    let credential_id = credential_a.id;
    repo.upsert(credential_a)
        .await
        .expect("Failed to seed credential");

    // Authenticate as tenant B
    let token_b = utils::create_test_bearer_token(tenant_b);

    // Act — tenant B tries to delete tenant A's credential
    let response = client
        .delete(format!("{base_url}/api/v1/credentials/{credential_id}"))
        .header("Authorization", format!("Bearer {token_b}"))
        .send()
        .await
        .expect("Failed to send request");

    // Assert — returns 404 (not 403) to avoid leaking credential existence
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["error"], "credential_not_found");

    // Assert — tenant A's credential is still present
    let still_present = repo
        .find_by_id(credential_id, tenant_a)
        .await
        .expect("Credential should still exist for tenant A");
    assert_eq!(still_present.id, credential_id);
}

#[tokio::test]
async fn delete_nonexistent_credential_returns_404() {
    // Arrange
    let (base_url, _) = spawn_server_with_repo().await;
    let client = Client::new();

    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let nonexistent_id = Uuid::new_v4();

    // Act
    let response = client
        .delete(format!("{base_url}/api/v1/credentials/{nonexistent_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["error"], "credential_not_found");
}
