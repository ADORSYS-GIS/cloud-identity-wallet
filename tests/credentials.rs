mod utils;

use cloud_identity_wallet::domain::models::credential::{
    Credential, CredentialDisplay, CredentialDisplayMetadata, CredentialFormat, CredentialStatus,
};
use cloud_identity_wallet::domain::ports::CredentialRepo;
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

/// Create display metadata for a credential.
fn make_display_metadata(credential: &Credential) -> CredentialDisplayMetadata {
    CredentialDisplayMetadata {
        display: CredentialDisplay {
            name: credential.credential_types[0].clone(),
            ..Default::default()
        },
        issuer_name: credential.issuer.clone(),
        credential_type: credential.credential_types[0].clone(),
    }
}

#[tokio::test]
async fn list_credentials_returns_empty_list_when_no_credentials_exist() {
    // Arrange
    let base_url = utils::spawn_server().await.base_url;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

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
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = make_credential(tenant_id);
    let credential_id = credential.id;
    let display_metadata = make_display_metadata(&credential);
    server
        .credential_repo
        .upsert(credential, Some(display_metadata))
        .await
        .unwrap();

    // Act
    let response = Client::new()
        .get(format!("{}/api/v1/credentials", server.base_url))
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
    assert_eq!(
        list[0]["display"]["credential_type"],
        "eu.europa.ec.eudi.pid.1"
    );
    assert_eq!(
        list[0]["display"]["issuer_name"],
        "https://issuer.example.com"
    );
}

#[tokio::test]
async fn list_credentials_does_not_return_other_tenants_credentials() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    // Credential belongs to tenant A
    let credential_a = make_credential(tenant_a);
    let display_metadata_a = make_display_metadata(&credential_a);
    server
        .credential_repo
        .upsert(credential_a, Some(display_metadata_a))
        .await
        .unwrap();

    // Act: request as tenant B
    let response = Client::new()
        .get(format!("{}/api/v1/credentials", server.base_url))
        .bearer_auth(utils::create_test_bearer_token(tenant_b))
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
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let mut revoked = make_credential(tenant_id);
    revoked.status = CredentialStatus::Revoked;
    let display_revoked = make_display_metadata(&revoked);
    server
        .credential_repo
        .upsert(revoked, Some(display_revoked))
        .await
        .unwrap();

    let active = make_credential(tenant_id);
    let display_active = make_display_metadata(&active);
    server
        .credential_repo
        .upsert(active, Some(display_active))
        .await
        .unwrap(); // active

    // Act: filter for active only
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?status=active",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: only the active credential is returned
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn list_credentials_returns_400_for_invalid_status() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    // Act
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?status=invalid_value",
            server.base_url
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
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let mut mdoc = make_credential(tenant_id);
    mdoc.format = CredentialFormat::Mdoc;
    let display_mdoc = make_display_metadata(&mdoc);
    server
        .credential_repo
        .upsert(mdoc, Some(display_mdoc))
        .await
        .unwrap();

    let sdjwt = make_credential(tenant_id);
    let display_sdjwt = make_display_metadata(&sdjwt);
    server
        .credential_repo
        .upsert(sdjwt, Some(display_sdjwt))
        .await
        .unwrap(); // dc+sd-jwt

    // Act: filter for mso_mdoc only
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?format=mso_mdoc",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn list_credentials_returns_400_for_invalid_format() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    // Act
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?format=not_a_format",
            server.base_url
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
async fn list_credentials_requires_authentication() {
    // Arrange
    let server = utils::spawn_server().await;

    // Act: no Authorization header
    let response = Client::new()
        .get(format!("{}/api/v1/credentials", server.base_url))
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn get_credential_returns_credential_for_owner() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let credential = make_credential(tenant_id);
    let id = credential.id;
    let display_metadata = make_display_metadata(&credential);
    server
        .credential_repo
        .upsert(credential, Some(display_metadata))
        .await
        .unwrap();

    // Act
    let response = Client::new()
        .get(format!("{}/api/v1/credentials/{id}", server.base_url))
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
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);
    let random_id = Uuid::new_v4();

    // Act
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials/{random_id}",
            server.base_url
        ))
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
    let server = utils::spawn_server().await;
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    let credential = make_credential(owner_id);
    let id = credential.id;
    let display_metadata = make_display_metadata(&credential);
    server
        .credential_repo
        .upsert(credential, Some(display_metadata))
        .await
        .unwrap();

    // Act: request as a different tenant
    let response = Client::new()
        .get(format!("{}/api/v1/credentials/{id}", server.base_url))
        .bearer_auth(utils::create_test_bearer_token(other_id))
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
    let server = utils::spawn_server().await;
    let id = Uuid::new_v4();

    // Act: no Authorization header
    let response = Client::new()
        .get(format!("{}/api/v1/credentials/{id}", server.base_url))
        .send()
        .await
        .unwrap();

    // Assert
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn list_credentials_filters_by_issuer() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let mut other_issuer = make_credential(tenant_id);
    other_issuer.issuer = "https://other-issuer.example.com".to_string();
    let display_other = make_display_metadata(&other_issuer);
    server
        .credential_repo
        .upsert(other_issuer, Some(display_other))
        .await
        .unwrap();

    let known_issuer = make_credential(tenant_id);
    let display_known = make_display_metadata(&known_issuer);
    server
        .credential_repo
        .upsert(known_issuer, Some(display_known))
        .await
        .unwrap(); // issuer.example.com

    // Act: filter for the known issuer only
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?issuer=https://issuer.example.com",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: only the credential from the requested issuer is returned
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    let list = body["credentials"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        list[0]["display"]["issuer_name"],
        "https://issuer.example.com"
    );
}

#[tokio::test]
async fn list_credentials_returns_expires_at_when_credential_has_expiry() {
    // Arrange: credential with a valid_until set
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let mut expiring = make_credential(tenant_id);
    expiring.valid_until = Some(time::UtcDateTime::now());
    let id = expiring.id;
    let display_metadata = make_display_metadata(&expiring);
    server
        .credential_repo
        .upsert(expiring, Some(display_metadata))
        .await
        .unwrap();

    // Act
    let response = Client::new()
        .get(format!("{}/api/v1/credentials/{id}", server.base_url))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: expires_at is present and is a non-null string
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["expires_at"].is_string(),
        "expected expires_at to be a date-time string, got: {}",
        body["expires_at"]
    );
}

#[tokio::test]
async fn list_credentials_credential_types_filter_excludes_unrelated_types() {
    // Arrange: credential with type.a; filter asks for type.b
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    let mut cred = make_credential(tenant_id);
    cred.credential_types = vec!["type.a".to_string()];
    let display_metadata = make_display_metadata(&cred);
    server
        .credential_repo
        .upsert(cred, Some(display_metadata))
        .await
        .unwrap();

    // Act: filter by a type the credential does not have
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?credential_types=type.b",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: no credentials returned
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["credentials"], serde_json::json!([]));
}

#[tokio::test]
async fn list_credentials_returns_400_for_invalid_issuer_uri() {
    // Arrange
    let server = utils::spawn_server().await;
    let tenant_id = Uuid::new_v4();
    let token = utils::create_test_bearer_token(tenant_id);

    // Act: issuer param is not a valid URI
    let response = Client::new()
        .get(format!(
            "{}/api/v1/credentials?issuer=not-a-uri",
            server.base_url
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    // Assert: 400 Bad Request
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}
