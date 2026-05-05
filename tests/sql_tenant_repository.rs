//! Integration tests for SQL tenant repository.

use cloud_identity_wallet::domain::models::tenants::{
    RegisterTenantRequest, SignAlgorithm, TenantError,
};
use cloud_identity_wallet::domain::ports::TenantRepo;
use cloud_identity_wallet::outbound::{MemoryTenantRepo, SqlTenantRepo, TenantKeyAlg};
use cloud_wallet_crypto::{
    ecdsa::KeyPair as EcdsaKeyPair,
    ed25519::KeyPair as Ed25519KeyPair,
    rsa::{KeyPair as RsaKeyPair, RsaKeySize},
};
use cloud_wallet_kms::provider::LocalProvider;
use sqlx::any::AnyPoolOptions;
use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};
use uuid::Uuid;

fn assert_valid_pkcs8(algorithm: SignAlgorithm, der: &[u8]) {
    match algorithm {
        SignAlgorithm::Ecdsa => {
            EcdsaKeyPair::from_pkcs8_der(der).expect("ECDSA key should be valid PKCS#8");
        }
        SignAlgorithm::EdDsa => {
            Ed25519KeyPair::from_pkcs8_der(der).expect("Ed25519 key should be valid PKCS#8");
        }
        SignAlgorithm::Rsa => {
            RsaKeyPair::from_pkcs8_der(der).expect("RSA key should be valid PKCS#8");
        }
    }
}

#[tokio::test]
async fn test_sql_tenant_repository_create() {
    // Install default drivers
    sqlx::any::install_default_drivers();

    // Create an in-memory SQLite database
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    // Create repository and initialize schema
    let repo = SqlTenantRepo::new(pool, TenantKeyAlg::EdDsa, LocalProvider::new());
    repo.init_schema()
        .await
        .expect("Failed to initialize schema");

    // Test creating a tenant
    let request = RegisterTenantRequest {
        name: "Test Tenant".to_string(),
    };

    let response = repo.create(request).await.expect("Failed to create tenant");

    assert_eq!(response.name, "Test Tenant");
    assert!(!response.tenant_id.is_empty());
}

#[tokio::test]
async fn test_sql_tenant_repo_find_key_roundtrip() {
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default()
        .with_tag("18-alpine")
        .start()
        .await
        .expect("Failed to start Postgres container");

    let connection_string = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await.unwrap(),
        container.get_host_port_ipv4(5432).await.unwrap()
    );

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to PostgreSQL");

    let repo = SqlTenantRepo::new(pool, TenantKeyAlg::EdDsa, LocalProvider::new());
    repo.init_schema()
        .await
        .expect("Failed to initialize schema");

    let response = repo
        .create(RegisterTenantRequest {
            name: "Roundtrip Tenant".to_string(),
        })
        .await
        .expect("Failed to create tenant");
    let id = Uuid::parse_str(&response.tenant_id).expect("tenant_id should be UUID");

    let tenant_key = repo.find_key(id).await.expect("Failed to fetch tenant key");
    assert_eq!(tenant_key.algorithm, SignAlgorithm::EdDsa);
    assert!(!tenant_key.der_bytes.is_empty());
    assert_valid_pkcs8(tenant_key.algorithm, tenant_key.der_bytes.expose());
}

#[tokio::test]
async fn test_sql_tenant_repo_find_key_not_found() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repo = SqlTenantRepo::new(pool, TenantKeyAlg::EdDsa, LocalProvider::new());
    repo.init_schema()
        .await
        .expect("Failed to initialize schema");

    let unknown_id = Uuid::new_v4();
    let result = repo.find_key(unknown_id).await;
    assert!(matches!(result, Err(TenantError::NotFound { id }) if id == unknown_id));
}

#[tokio::test]
async fn test_sql_tenant_repository_validates_name() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repo = SqlTenantRepo::new(pool, TenantKeyAlg::EdDsa, LocalProvider::new());
    repo.init_schema()
        .await
        .expect("Failed to initialize schema");

    // Test with empty name
    let request = RegisterTenantRequest {
        name: "".to_string(),
    };

    let result = repo.create(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_sql_tenant_repository_trims_name() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repo = SqlTenantRepo::new(pool, TenantKeyAlg::EdDsa, LocalProvider::new());
    repo.init_schema()
        .await
        .expect("Failed to initialize schema");

    // Test with whitespace
    let request = RegisterTenantRequest {
        name: "  Test Tenant  ".to_string(),
    };

    let response = repo.create(request).await.expect("Failed to create tenant");
    assert_eq!(response.name, "Test Tenant");
}

#[tokio::test]
async fn test_memory_tenant_repo_find_key_roundtrip() {
    let repo = MemoryTenantRepo::new();

    let response = repo
        .create(RegisterTenantRequest {
            name: "Memory Tenant".to_string(),
        })
        .await
        .expect("Failed to create tenant");
    let id = Uuid::parse_str(&response.tenant_id).expect("tenant_id should be UUID");

    let tenant_key = repo.find_key(id).await.expect("Failed to fetch tenant key");
    assert_eq!(tenant_key.algorithm, SignAlgorithm::Ecdsa);
    assert!(!tenant_key.der_bytes.is_empty());
    assert_valid_pkcs8(tenant_key.algorithm, tenant_key.der_bytes.expose());
}

#[tokio::test]
async fn test_memory_repo_find_key_with_cipher_roundtrip() {
    let repo =
        MemoryTenantRepo::with_cipher(TenantKeyAlg::Rsa(RsaKeySize::Rsa2048), LocalProvider::new());

    let response = repo
        .create(RegisterTenantRequest {
            name: "Memory Encrypted Tenant".to_string(),
        })
        .await
        .expect("Failed to create tenant");
    let id = Uuid::parse_str(&response.tenant_id).expect("tenant_id should be UUID");

    let tenant_key = repo.find_key(id).await.expect("Failed to fetch tenant key");
    assert_eq!(tenant_key.algorithm, SignAlgorithm::Rsa);
    assert!(!tenant_key.der_bytes.is_empty());
    assert_valid_pkcs8(tenant_key.algorithm, tenant_key.der_bytes.expose());
}

#[tokio::test]
async fn test_memory_repo_find_key_not_found() {
    let repo = MemoryTenantRepo::new();
    let unknown_id = Uuid::new_v4();

    let result = repo.find_key(unknown_id).await;
    assert!(matches!(result, Err(TenantError::NotFound { id }) if id == unknown_id));
}
