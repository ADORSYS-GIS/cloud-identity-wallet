//! Storage backend compatibility tests to ensure all backends behave consistently.

pub mod utils;

use cloud_identity_wallet::{
    domain::{
        models::credential::{CredentialError, CredentialFilter, CredentialStatus},
        ports::CredentialRepo,
    },
    outbound::{MemoryCredentialRepo, SqlCredentialRepo},
};
use sqlx::any::AnyPoolOptions;
use uuid::Uuid;

/// Generic CRUD suite that all repository backends must pass.
async fn test_repository_backend<R: CredentialRepo>(
    repository: &R,
    tenant_a: Uuid,
    tenant_b: Uuid,
) {
    let credential_a = utils::sample_credential(tenant_a);
    let mut credential_b = utils::sample_credential(tenant_b);
    credential_b.subject = Some("did:example:bob".to_string());
    credential_b.external_id = Some("https://issuer.example/ext-456".to_string());

    // Inserts credentials
    let inserted_id = repository.upsert(credential_a.clone()).await.unwrap();
    assert_eq!(inserted_id, credential_a.id);
    repository.upsert(credential_b.clone()).await.unwrap();

    // Finds credential for tenant A
    let found = repository
        .find_by_id(credential_a.id, credential_a.tenant_id)
        .await
        .unwrap();
    assert_eq!(found.id, credential_a.id);
    assert_eq!(found.raw_credential, credential_a.raw_credential);
    assert_eq!(found.credential_types, credential_a.credential_types);

    // Lists credentials for tenant A
    let listed = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            credential_types: Some(credential_a.credential_types.clone()),
            format: Some(credential_a.format),
            issuer: Some(credential_a.issuer.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    // Should find only credential A
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, credential_a.id);

    // Lists credentials with reversed types (should not match)
    let mut reversed_types = credential_a.credential_types.clone();
    reversed_types.reverse();
    let mismatch = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_a),
            credential_types: Some(reversed_types),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(mismatch.is_empty());

    // Updates credential
    let mut updated = found.clone();
    updated.status = CredentialStatus::Revoked;
    updated.is_revoked = true;
    updated.raw_credential = "updated.payload.value".to_string();
    repository.upsert(updated.clone()).await.unwrap();

    // Reloads credential to verify update
    let reloaded = repository
        .find_by_id(updated.id, updated.tenant_id)
        .await
        .unwrap();
    assert_eq!(reloaded.status, CredentialStatus::Revoked);
    assert!(reloaded.is_revoked);
    assert_eq!(reloaded.raw_credential, "updated.payload.value");

    repository
        .delete(credential_a.id, credential_a.tenant_id)
        .await
        .unwrap();
    // Verifies credential is deleted
    assert!(matches!(
        repository
            .find_by_id(credential_a.id, credential_a.tenant_id)
            .await,
        Err(CredentialError::NotFound { .. })
    ));

    // Verifies tenant B still has its credential
    let tenant_b_records = repository
        .list(CredentialFilter {
            tenant_id: Some(tenant_b),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(tenant_b_records.len(), 1);
    assert_eq!(tenant_b_records[0].id, credential_b.id);
}

#[tokio::test]
async fn test_inmemory_storage_backend() {
    let repository = MemoryCredentialRepo::new();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    test_repository_backend(&repository, tenant_a, tenant_b).await;
}

#[tokio::test]
async fn test_sqlite_storage_backend() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;
}

#[tokio::test]
async fn test_postgres_storage_backend() {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

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

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;
}

#[tokio::test]
async fn test_mysql_storage_backend() {
    use testcontainers_modules::mysql::Mysql;
    use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

    let container = Mysql::default()
        .with_tag("9-oracle")
        .start()
        .await
        .expect("Failed to start MySQL container");

    let connection_string = format!(
        "mysql://{}:{}/test",
        container.get_host().await.unwrap(),
        container.get_host_port_ipv4(3306).await.unwrap()
    );

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to MySQL");

    let repository = SqlCredentialRepo::new(pool.clone());
    repository.init_schema().await.unwrap();

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    utils::insert_tenant(&pool, tenant_a, "Tenant A").await;
    utils::insert_tenant(&pool, tenant_b, "Tenant B").await;

    test_repository_backend(&repository, tenant_a, tenant_b).await;
}
