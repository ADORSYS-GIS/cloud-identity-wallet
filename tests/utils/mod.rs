#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config,
    domain::service::Service,
    outbound::{SqlTenantRepo, TenantKeyAlg},
    server::{Server, sse::SseEvent},
    session::MemorySession,
};
use cloud_wallet_kms::provider::LocalProvider;
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciConfig, Oid4vciClient};
use sqlx::{AnyPool, ConnectOptions};
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    // Create in-memory database for testing
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let tenant_repo = SqlTenantRepo::new(pool.clone(), TenantKeyAlg::EdDsa, LocalProvider::new());
    tenant_repo.init_schema().await.unwrap();

    // Create session store and SSE broadcast
    let session_store = MemorySession::default();
    let (sse_broadcast, _) = tokio::sync::broadcast::channel::<SseEvent>(16);

    // Create OID4VCI client
    let oid4vci_config = Oid4vciConfig::new(
        config.wallet.client_id.clone(),
        config.wallet.redirect_uri.clone(),
    );
    let oid4vci_client = Oid4vciClient::new(oid4vci_config).unwrap();

    let service = Service::new(session_store, tenant_repo, oid4vci_client, sse_broadcast);
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}

pub fn sample_credential(tenant_id: Uuid) -> cloud_identity_wallet::domain::models::credential::Credential {
    use cloud_identity_wallet::domain::models::credential::{Credential, CredentialFormat, CredentialStatus};
    
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
