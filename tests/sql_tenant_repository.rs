//! Integration tests for SQL tenant repository.

use cloud_identity_wallet::domain::models::tenants::RegisterTenantRequest;
use cloud_identity_wallet::domain::ports::TenantRepository;
use cloud_identity_wallet::outbound::SqlTenantRepository;
use sqlx::any::AnyPoolOptions;

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
    let repo = SqlTenantRepository::new(pool);
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
async fn test_sql_tenant_repository_validates_name() {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let repo = SqlTenantRepository::new(pool);
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

    let repo = SqlTenantRepository::new(pool);
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
