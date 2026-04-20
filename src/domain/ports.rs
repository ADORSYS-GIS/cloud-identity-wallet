//! Tenant repository port and validation logic.

use async_trait::async_trait;

// Re-export from models
pub use super::models::{Tenant, RegisterTenantRequest, TenantResponse, TenantErrorResponse, TenantError};

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync + 'static {
    /// Creates a new tenant and returns the response with generated ID and timestamp.
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError>;
}
