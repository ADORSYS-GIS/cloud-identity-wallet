/*
   This module specifies the API by which external modules interact with the wallet domain.
*/
use async_trait::async_trait;

use crate::domain::models::tenants::{RegisterTenantRequest, TenantError, TenantResponse};

// Re-export from models

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync + std::fmt::Debug + 'static {
    /// Creates a new tenant and returns the response with generated ID and timestamp.
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError>;
}
