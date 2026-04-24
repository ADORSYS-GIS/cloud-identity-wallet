/*
   This module specifies the API by which external modules interact with the wallet domain.
*/
use async_trait::async_trait;

use crate::domain::models::consent::SessionError;
use crate::domain::models::tenants::{RegisterTenantRequest, TenantError, TenantResponse};
use crate::session::IssuanceSession;

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync + 'static {
    /// Creates a new tenant and returns the response with generated ID and timestamp.
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    async fn get(&self, session_id: &str) -> Result<Option<IssuanceSession>, SessionError>;
    async fn save(&self, session: &IssuanceSession) -> Result<(), SessionError>;
    async fn delete(&self, session_id: &str) -> Result<(), SessionError>;
}
