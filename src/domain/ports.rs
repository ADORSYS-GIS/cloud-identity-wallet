/*
   This module specifies the API by which external modules interact with the wallet domain.
*/
use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::models::credential::{Credential, CredentialError, CredentialFilter};
use crate::domain::models::tenants::{
    RegisterTenantRequest, TenantError, TenantKey, TenantResponse,
};

/// Repository trait for tenant persistence.
#[async_trait]
pub trait TenantRepo: Send + Sync + 'static {
    /// Creates a new tenant and returns the response with generated ID and timestamp.
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError>;

    /// Retrieves a tenant key material by its ID.
    async fn find_key(&self, id: Uuid) -> Result<TenantKey, TenantError>;
}

/// Common interface for Credential persistence.
#[async_trait]
pub trait CredentialRepo: Send + Sync + 'static {
    /// Upserts (inserts or updates) a Credential.
    ///
    /// If a Credential with the same ID and tenant ID already exists, it is updated;
    /// otherwise, a new Credential is inserted. Returns the UUID of the credential.
    async fn upsert(&self, credential: Credential) -> Result<uuid::Uuid, CredentialError>;

    /// Retrieves a Credential by its ID and tenant ID.
    ///
    /// Returns [`CredentialError::NotFound`] if the credential is not found.
    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential, CredentialError>;

    /// Lists credentials that match the given filter criteria.
    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>, CredentialError>;

    /// Deletes a Credential by its ID and tenant ID.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<(), CredentialError>;
}
