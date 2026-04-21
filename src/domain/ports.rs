//! Tenant repository port and validation logic.

use async_trait::async_trait;

use crate::domain::models::tenants::{RegisterTenantRequest, TenantError, TenantResponse};

// Re-export from models

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync + 'static {
    /// Creates a new tenant and returns the response with generated ID and timestamp.
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError>;
}
