/*
   This module specifies the API by which external modules interact with the wallet domain.
*/
use std::pin::Pin;

use async_trait::async_trait;
use futures::stream::Stream;
use uuid::Uuid;

use crate::domain::models::credential::{Credential, CredentialError, CredentialFilter};
use crate::domain::models::issuance::{IssuanceError, IssuanceEvent, IssuanceTask};
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

/// A pinned async stream of [`IssuanceEvent`] items.
pub type IssuanceEventStream = Pin<Box<dyn Stream<Item = IssuanceEvent> + Send>>;

/// An issuance task queue for background task processing.
///
/// Implementations handle the internal mechanics of locking, leasing, stale
/// reclaim, and crash resilience.
#[async_trait]
pub trait IssuanceTaskQueue: Send + Sync + 'static {
    /// Push an issuance task onto the queue for background processing.
    async fn push(&self, task: &IssuanceTask) -> Result<(), IssuanceError>;

    /// Claim the next available task from the queue.
    ///
    /// Returned tasks are owned by the caller until they are acknowledged or
    /// become stale according to the backend's reclaim policy. Returns `None`
    /// if no task is currently available.
    async fn pop(&self) -> Result<Option<IssuanceTask>, IssuanceError>;

    /// Mark a previously claimed task as terminally processed and remove it
    /// from the queue.
    ///
    /// Queue implementations should make this idempotent enough that calling it
    /// for a task that was not popped from that backend is a no-op.
    async fn ack(&self, task: &IssuanceTask) -> Result<(), IssuanceError>;
}

/// An event publisher for issuance events.
#[async_trait]
pub trait IssuanceEventPublisher: Send + Sync + 'static {
    /// Publish an issuance event for a session.
    async fn publish(&self, event: &IssuanceEvent) -> Result<(), IssuanceError>;
}

/// A subscriber for issuance events.
#[async_trait]
pub trait IssuanceEventSubscriber: Send + Sync + 'static {
    /// Subscribe to events for a specific session.
    ///
    /// Returns a stream that yields events as they are published.
    /// The stream should auto-terminate after a terminal event.
    async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream, IssuanceError>;
}
