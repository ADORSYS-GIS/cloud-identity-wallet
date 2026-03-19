//! End-to-end integration tests for AWS KMS provider with multiple storage backends.

#![cfg(all(feature = "aws-kms", feature = "sqlx-backend"))]

mod common;

use cloud_wallet_kms::provider::{AwsProvider, Provider};
use cloud_wallet_kms::storage::SqlxBackend;
use cloud_wallet_kms::storage::Storage;
use sqlx::any::AnyPoolOptions;
use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

/// Generic end-to-end test that works with any storage backend.
async fn test_provider_with_storage_backend<S>(storage: S, hostname: &str)
where
    S: Storage + Send + Sync,
{
    // Setup LocalStack and get AWS config
    let aws_config = common::setup().await;

    // Create a new AwsProvider with the given storage backend
    let provider = AwsProvider::new(&aws_config, hostname, storage);

    // Prepare test data
    let aad = common::SAMPLE_AAD;
    let mut plaintext = common::SAMPLE_PLAINTEXT.to_vec();
    let original_plaintext = plaintext.clone();

    // Encrypt the data
    provider
        .encrypt(aad, &mut plaintext)
        .await
        .expect("Encryption failed");

    // Decrypt the data
    let decrypted = provider
        .decrypt(aad, &mut plaintext)
        .await
        .expect("Decryption failed");

    // Verify that the decrypted data matches the original plaintext
    assert_eq!(
        decrypted,
        original_plaintext.as_slice(),
        "Decrypted data does not match original plaintext"
    );
}

// Test with InMemoryBackend
#[cfg(feature = "memory-backend")]
#[tokio::test]
async fn test_aws_provider_e2e_inmemory() {
    let storage = cloud_wallet_kms::storage::InMemoryBackend::new();
    test_provider_with_storage_backend(storage, "e2e-inmemory").await;
}

// Test with SqlxBackend (SQLite)
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_aws_provider_e2e_sqlite() {
    // Create an in-memory SQLite database
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    // Initialize the storage and its schema
    let storage = SqlxBackend::new(pool);
    storage
        .init_schema()
        .await
        .expect("Failed to initialize schema");

    test_provider_with_storage_backend(storage, "e2e-sqlite").await;
}

// Test with SqlxBackend (PostgreSQL)
#[cfg(feature = "postgres")]
#[tokio::test]
async fn test_aws_provider_e2e_postgres() {
    use testcontainers_modules::postgres::Postgres;

    // Start a PostgreSQL container
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

    // Create a connection pool
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to PostgreSQL");

    // Initialize the storage and its schema
    let storage = SqlxBackend::new(pool);
    storage
        .init_schema()
        .await
        .expect("Failed to initialize schema");

    test_provider_with_storage_backend(storage, "e2e-postgres").await;
}

// Test with SqlxBackend (MySQL)
#[cfg(feature = "mysql")]
#[tokio::test]
async fn test_aws_provider_e2e_mysql() {
    use testcontainers_modules::mysql::Mysql;

    // Start a MySQL container
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

    // Create a connection pool
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&connection_string)
        .await
        .expect("Failed to connect to MySQL");

    // Initialize the storage and its schema
    let storage = SqlxBackend::new(pool);
    storage
        .init_schema()
        .await
        .expect("Failed to initialize schema");

    test_provider_with_storage_backend(storage, "e2e-mysql").await;
}
