#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::credential::{Credential, CredentialFormat, CredentialStatus},
        service::Service,
    },
    outbound::MemoryTenantRepo,
    server::Server,
    session::MemorySession,
};
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};
use sqlx::{AnyPool, ConnectOptions};
use std::time::Duration;
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

pub async fn spawn_server() -> String {
    spawn_server_inner(false, false).await
}

#[allow(dead_code)]
pub async fn spawn_server_with_mock_issuer() -> String {
    spawn_server_inner(true, true).await
}

async fn spawn_server_inner(accept_untrusted_hosts: bool, enable_test_bypass: bool) -> String {
    // Install default drivers for sqlx
    sqlx::any::install_default_drivers();

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();

    let oid4vci_config = Oid4vciClientConfig::new(
        &config.oid4vci.client_id,
        config.oid4vci.redirect_uri.clone(),
    )
    .timeout(Duration::from_secs(5))
    .accept_untrusted_hosts(accept_untrusted_hosts)
    .https_only(!accept_untrusted_hosts);
    let oid4vci_client = Oid4vciClient::new(oid4vci_config).unwrap();

    let service = Service::new(session_store, tenant_repo, oid4vci_client);
    let server = Server::new_with_test_bypass(&config, service, enable_test_bypass)
        .await
        .unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}

pub fn sample_credential(tenant_id: Uuid) -> Credential {
    Credential {
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
        status_location: Some(Url::parse("https://status.example/42").unwrap()),
        status_index: Some(42),
        raw_credential: "eyJhbGciOiJFZERTQSJ9.payload.signature".to_string(),
    }
}

pub async fn insert_tenant(pool: &AnyPool, id: Uuid, name: &str) {
    let url = pool.connect_options().to_url_lossy();
    let is_postgres =
        url.as_str().starts_with("postgres://") || url.as_str().starts_with("postgresql://");
    let key_algorithm = "eddsa";
    let key_material = vec![0u8; 32];
    let created_at = UtcDateTime::now().unix_timestamp();

    let query = if is_postgres {
        "INSERT INTO tenants (id, name, key_algorithm, key_material, created_at) VALUES ($1, $2, $3, $4, $5)"
    } else {
        "INSERT INTO tenants (id, name, key_algorithm, key_material, created_at) VALUES (?, ?, ?, ?, ?)"
    };

    sqlx::query(query)
        .bind(id.to_string())
        .bind(name)
        .bind(key_algorithm)
        .bind(key_material)
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
}
