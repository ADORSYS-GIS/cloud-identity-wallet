//! Storage backend compatibility tests to ensure all backends behave consistently.

#![cfg(feature = "sqlx-backend")]

mod common;

use cloud_wallet_crypto::aead::Algorithm;
use cloud_wallet_kms::{
    AeadAlgorithm, DataEncryptionKey, DekId, MasterId,
    storage::{InMemoryBackend, SqlxBackend, Storage},
};
use sqlx::any::AnyPoolOptions;
use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};
use time::UtcDateTime;

/// Generic test suite that all storage backends must pass
async fn test_storage_backend<S: Storage>(storage: S) {
    // Store and retrieve
    let dek = DataEncryptionKey {
        id: DekId::new("compat-test-001"),
        master_key_id: MasterId::new("compat-mk-001"),
        encrypted_key: vec![0, 1, 2, 3, 4, 5, 128, 255].into(),
        plaintext_key: None,
        algorithm: AeadAlgorithm(Algorithm::AesGcm256),
        created_at: UtcDateTime::from_unix_timestamp(1_714_182_400).unwrap(),
        last_accessed: None,
    };

    storage.upsert_dek(&dek).await.unwrap();
    let retrieved = storage.get_dek(&dek.id).await.unwrap().unwrap();
    assert_eq!(retrieved.id.as_str(), dek.id.as_str());
    assert_eq!(retrieved.master_key_id.as_str(), dek.master_key_id.as_str());
    assert_eq!(*retrieved.encrypted_key, *dek.encrypted_key);
    assert!(retrieved.plaintext_key.is_none());
    assert_eq!(retrieved.algorithm, dek.algorithm);
    assert_eq!(retrieved.created_at, dek.created_at);
    assert!(retrieved.last_accessed.is_some());

    // Update
    let mut updated = retrieved.clone();
    updated.last_accessed = Some(UtcDateTime::now());
    storage.upsert_dek(&updated).await.unwrap();
}

#[cfg(feature = "memory-backend")]
#[tokio::test]
async fn test_inmemory_storage() {
    common::init_tracing();
    let storage = InMemoryBackend::new();
    test_storage_backend(storage).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_sqlite_storage() {
    common::init_tracing();

    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let storage = SqlxBackend::new(pool);
    storage.init_schema().await.unwrap();

    test_storage_backend(storage).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn test_postgres_storage() {
    use testcontainers_modules::postgres::Postgres;

    common::init_tracing();

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

    let storage = SqlxBackend::new(pool);
    storage.init_schema().await.unwrap();

    test_storage_backend(storage).await;
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_mysql_storage() {
    use testcontainers_modules::mysql::Mysql;

    common::init_tracing();

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

    let storage = SqlxBackend::new(pool);
    storage.init_schema().await.unwrap();

    test_storage_backend(storage).await;
}
