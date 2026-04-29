mod utils;

use cloud_identity_wallet::domain::models::credential::{
    Credential, CredentialFormat, CredentialStatus,
};
use reqwest::Client;
use time::UtcDateTime;
use uuid::Uuid;

/// Build a minimal `Credential` owned by `tenant_id`.
fn make_credential(tenant_id: Uuid) -> Credential {
    Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer: "https://issuer.example.com".to_string(),
        subject: None,
        credential_types: vec!["eu.europa.ec.eudi.pid.1".to_string()],
        format: CredentialFormat::SdJwtVc,
        external_id: None,
        status: CredentialStatus::Active,
        issued_at: UtcDateTime::now(),
        valid_until: None,
        is_revoked: false,
        status_location: None,
        status_index: None,
        raw_credential: "dummy".to_string(),
    }
}

#[tokio::test]
async fn list_credentials_returns_empty_list_when_no_credentials_exist() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    // Act
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["credentials"], serde_json::json!([]));
}

#[tokio::test]
async fn list_credentials_returns_credentials_for_authenticated_tenant() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    let credential = make_credential(tenant_id);
    let credential_id = credential.id;
    repo.upsert(credential).await.unwrap();

    // Act
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], credential_id.to_string());
    assert_eq!(list[0]["format"], "dc+sd-jwt");
    assert_eq!(list[0]["status"], "active");
    assert_eq!(list[0]["issuer"], "https://issuer.example.com");
}

#[tokio::test]
async fn list_credentials_does_not_return_other_tenants_credentials() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Credential belongs to tenant A
    repo.upsert(make_credential(tenant_a)).await.unwrap();

    // Act: request as tenant B
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials"))
        .bearer_auth(utils::create_bearer_token(&tenant_b))
        .send()
        .await
        .unwrap();

    // Assert: tenant B sees nothing
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["credentials"], serde_json::json!([]));
}

#[tokio::test]
async fn list_credentials_filters_by_valid_status() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    let mut revoked = make_credential(tenant_id);
    revoked.status = CredentialStatus::Revoked;
    repo.upsert(revoked).await.unwrap();
    repo.upsert(make_credential(tenant_id)).await.unwrap(); // active

    // Act: filter for active only
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials?status=active"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: only the active credential is returned
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["status"], "active");
}

#[tokio::test]
async fn list_credentials_returns_400_for_invalid_status() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    // Act
    let response = Client::new()
        .get(format!(
            "{base_url}/api/v1/credentials?status=invalid_value"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn list_credentials_filters_by_valid_format() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    let mut mdoc = make_credential(tenant_id);
    mdoc.format = CredentialFormat::Mdoc;
    repo.upsert(mdoc).await.unwrap();
    repo.upsert(make_credential(tenant_id)).await.unwrap(); // dc+sd-jwt

    // Act: filter for mso_mdoc only
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials?format=mso_mdoc"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["format"], "mso_mdoc");
}

#[tokio::test]
async fn list_credentials_returns_400_for_invalid_format() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    // Act
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials?format=not_a_format"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn list_credentials_requires_authentication() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;

    // Act: no Authorization header
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials"))
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn get_credential_returns_credential_for_owner() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);

    let credential = make_credential(tenant_id);
    let id = credential.id;
    repo.upsert(credential).await.unwrap();

    // Act
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials/{id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body["format"], "dc+sd-jwt");
    assert_eq!(body["status"], "active");
    assert!(body.get("issued_at").is_some());
}

#[tokio::test]
async fn get_credential_returns_404_for_nonexistent_id() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_bearer_token(&tenant_id);
    let random_id = Uuid::new_v4();

    // Act
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials/{random_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 404);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "credential_not_found");
}

#[tokio::test]
async fn get_credential_returns_404_when_credential_belongs_to_different_tenant() {
    // Arrange
    let (base_url, repo) = utils::spawn_server_with_repo().await;
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    let credential = make_credential(owner_id);
    let id = credential.id;
    repo.upsert(credential).await.unwrap();

    // Act: request as a different tenant
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials/{id}"))
        .bearer_auth(utils::create_bearer_token(&other_id))
        .send()
        .await
        .unwrap();

    // Assert: no information about the credential is leaked
    assert_eq!(response.status(), 404);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "credential_not_found");
}

#[tokio::test]
async fn get_credential_requires_authentication() {
    // Arrange
    let (base_url, _repo) = utils::spawn_server_with_repo().await;
    let id = Uuid::new_v4();

    // Act: no Authorization header
    let response = Client::new()
        .get(format!("{base_url}/api/v1/credentials/{id}"))
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 401);
}
