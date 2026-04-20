//! SQL-based implementation of the TenantRepository trait.

use async_trait::async_trait;
use sqlx::AnyPool;
use uuid::Uuid;

use crate::domain::ports::{
    RegisterTenantRequest, TenantError, TenantRepository, TenantResponse,
};
use crate::domain::models::TenantName;

/// SQL-based tenant repository implementation.
#[derive(Debug, Clone)]
pub struct SqlTenantRepository {
    pool: AnyPool,
}

impl SqlTenantRepository {
    /// Creates a new SQL tenant repository with the given connection pool.
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Initializes the database schema for tenants.
    ///
    /// This should be called once during application startup to ensure
    /// the tenants table exists.
    pub async fn init_schema(&self) -> Result<(), TenantError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| TenantError::Backend(e.into()))?;

        Ok(())
    }
}

#[async_trait]
impl TenantRepository for SqlTenantRepository {
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError> {
        let validated_name = TenantName::validate(request.name.as_ref())
            .map_err(|e| TenantError::InvalidName(e))?;

        let id = Uuid::new_v4();
        let created_at = time::UtcDateTime::now();

        sqlx::query(
            r#"
            INSERT INTO tenants (id, name, created_at)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(id.to_string())
        .bind(validated_name.as_str())
        .bind(created_at.unix_timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| TenantError::Backend(e.into()))?;

        Ok(TenantResponse {
            tenant_id: id.to_string(),
            name: validated_name,
        })
    }
}
