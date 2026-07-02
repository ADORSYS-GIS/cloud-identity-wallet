/*
   This module specifies the API by which external modules interact with the wallet domain.
*/
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::Stream;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialDisplayMetadata, CredentialError, CredentialFilter, CredentialSummary,
};
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

#[async_trait]
impl TenantRepo for Arc<dyn TenantRepo> {
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError> {
        self.as_ref().create(request).await
    }

    async fn find_key(&self, id: Uuid) -> Result<TenantKey, TenantError> {
        self.as_ref().find_key(id).await
    }
}

/// Common interface for Credential persistence.
#[async_trait]
pub trait CredentialRepo: Send + Sync + 'static {
    /// Upserts (inserts or updates) a Credential.
    ///
    /// If a Credential with the same ID and tenant ID already exists, it is updated;
    /// otherwise, a new Credential is inserted. Returns the UUID of the credential.
    ///
    /// When `display` is [`Some`], the display metadata is persisted atomically
    /// alongside the credential within the same transaction.
    async fn upsert(
        &self,
        credential: Credential,
        display: Option<CredentialDisplayMetadata>,
    ) -> Result<uuid::Uuid, CredentialError>;

    /// Retrieves a Credential by its ID and tenant ID.
    ///
    /// Returns [`CredentialError::NotFound`] if the credential is not found.
    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential, CredentialError>;

    /// Lists credential summaries that match the given filter criteria.
    ///
    /// This listing path returns only display metadata needed for list rendering
    /// and does not load or decrypt the raw credential payload.
    async fn list(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<CredentialSummary>, CredentialError>;

    /// Deletes a Credential by its ID and tenant ID.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<(), CredentialError>;
}

#[async_trait]
impl CredentialRepo for Arc<dyn CredentialRepo> {
    async fn upsert(
        &self,
        credential: Credential,
        display: Option<CredentialDisplayMetadata>,
    ) -> Result<uuid::Uuid, CredentialError> {
        self.as_ref().upsert(credential, display).await
    }

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential, CredentialError> {
        self.as_ref().find_by_id(id, tenant_id).await
    }

    async fn list(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<CredentialSummary>, CredentialError> {
        self.as_ref().list(filter).await
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<(), CredentialError> {
        self.as_ref().delete(id, tenant_id).await
    }
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

#[async_trait]
impl IssuanceTaskQueue for Arc<dyn IssuanceTaskQueue> {
    async fn push(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        self.as_ref().push(task).await
    }

    async fn pop(&self) -> Result<Option<IssuanceTask>, IssuanceError> {
        self.as_ref().pop().await
    }

    async fn ack(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        self.as_ref().ack(task).await
    }
}

/// An event publisher for issuance events.
#[async_trait]
pub trait IssuanceEventPublisher: Send + Sync + 'static {
    /// Publish an issuance event for a session.
    async fn publish(&self, event: &IssuanceEvent) -> Result<(), IssuanceError>;
}

#[async_trait]
impl IssuanceEventPublisher for Arc<dyn IssuanceEventPublisher> {
    async fn publish(&self, event: &IssuanceEvent) -> Result<(), IssuanceError> {
        self.as_ref().publish(event).await
    }
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

#[async_trait]
impl IssuanceEventSubscriber for Arc<dyn IssuanceEventSubscriber> {
    async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream, IssuanceError> {
        self.as_ref().subscribe(session_id).await
    }
}
