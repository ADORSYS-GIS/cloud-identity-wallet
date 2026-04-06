//! # Storage Backends for Credential Persistence
//!
//! ## Provided Backends
//!
//! - [`SqlRepository`]: A persistent storage backend that supports any database
//!   compatible with `sqlx`, such as PostgreSQL, MySQL, and SQLite.
//! - [`InMemoryRepository`]: A volatile, in-memory storage backend intended
//!   for testing and development purposes.

#[cfg(feature = "memory-repo")]
pub(crate) mod memory;
#[cfg(any(feature = "postgres", feature = "mysql", feature = "sqlite"))]
pub(crate) mod sql;

#[cfg(feature = "memory-repo")]
pub use memory::InMemoryRepository;
#[cfg(any(feature = "postgres", feature = "mysql", feature = "sqlite"))]
pub use sql::SqlRepository;

use async_trait::async_trait;
use color_eyre::eyre::Report;
use uuid::Uuid;

use crate::credential::{Credential, CredentialFormat, CredentialStatus};

/// Result type for storage operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during storage operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage backend error: {0}")]
    Backend(Report),

    #[error("Credential not found for id={id}, tenant_id={tenant_id}")]
    NotFound { id: Uuid, tenant_id: Uuid },

    #[error("Invalid stored credential data: {0}")]
    InvalidData(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Storage error: {0}")]
    Other(String),
}

/// Common interface for Credential persistence.
#[async_trait]
pub trait CredentialRepository: Send + Sync + 'static {
    /// Upserts (inserts or updates) a Credential.
    ///
    /// If a Credential with the same ID and tenant ID already exists, it is updated;
    /// otherwise, a new Credential is inserted. Returns the UUID of the credential.
    async fn upsert(&self, credential: Credential) -> Result<uuid::Uuid>;

    /// Retrieves a Credential by its ID and tenant ID.
    ///
    /// Returns [`Error::NotFound`] if the credential is not found.
    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential>;

    /// Lists credentials that match the given filter criteria.
    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>>;

    /// Deletes a Credential by its ID and tenant ID.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<()>;
}

/// Filter criteria for listing credentials.
#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    pub tenant_id: Option<Uuid>,
    pub credential_types: Option<Vec<String>>,
    pub status: Option<CredentialStatus>,
    pub format: Option<CredentialFormat>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub exclude_expired: bool,
}

impl CredentialFilter {
    /// Checks if a credential matches the filter criteria.
    pub fn matches(&self, credential: &Credential) -> bool {
        if let Some(tenant_id) = self.tenant_id
            && credential.tenant_id != tenant_id
        {
            return false;
        }
        if let Some(status) = self.status
            && credential.status != status
        {
            return false;
        }
        if let Some(format) = self.format
            && credential.format != format
        {
            return false;
        }
        if let Some(issuer) = &self.issuer
            && credential.issuer != *issuer
        {
            return false;
        }
        if let Some(subject) = &self.subject
            && credential.subject.as_deref() != Some(subject.as_str())
        {
            return false;
        }
        if let Some(types) = &self.credential_types
            && &credential.credential_types != types
        {
            return false;
        }
        if self.exclude_expired
            && let Some(valid_until) = credential.valid_until
            && valid_until <= time::UtcDateTime::now()
        {
            return false;
        }
        true
    }
}

#[cfg(any(
    feature = "postgres",
    feature = "mysql",
    feature = "sqlite",
    feature = "memory-repo"
))]
mod cipher {
    use cloud_wallet_kms::{self as kms, provider::Provider};
    use std::sync::Arc;

    /// A dyn-compatible internal cipher abstraction.
    /// This is intentionally not pub.
    #[async_trait::async_trait]
    pub(super) trait Cipher: Send + Sync + 'static {
        async fn encrypt(&self, aad: &[u8], data: &mut Vec<u8>) -> cloud_wallet_kms::Result<()>;

        async fn decrypt<'a>(
            &self,
            aad: &[u8],
            data: &'a mut [u8],
        ) -> cloud_wallet_kms::Result<&'a [u8]>;
    }

    /// Newtype that wraps any KmsProvider and implements Cipher.
    struct KmsBridge<K>(K);

    #[async_trait::async_trait]
    impl<K: Provider + Send + Sync + 'static> Cipher for KmsBridge<K> {
        async fn encrypt(&self, aad: &[u8], data: &mut Vec<u8>) -> kms::Result<()> {
            self.0.encrypt(aad, data).await
        }

        async fn decrypt<'a>(&self, aad: &[u8], data: &'a mut [u8]) -> kms::Result<&'a [u8]> {
            self.0.decrypt(aad, data).await
        }
    }

    pub(super) fn from_provider<K>(provider: K) -> Arc<dyn Cipher>
    where
        K: Provider + Send + Sync + 'static,
    {
        Arc::new(KmsBridge(provider))
    }
}
