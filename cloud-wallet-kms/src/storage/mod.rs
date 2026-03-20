//! # Storage Backends for DEK Persistence
//!
//! ## Provided Backends
//!
//! - [`SqlxBackend`]: A persistent storage backend that supports any database
//!   compatible with `sqlx`, such as PostgreSQL, MySQL, and SQLite.
//! - [`InMemoryBackend`]: A volatile, in-memory storage backend intended
//!   for testing and development purposes.

use crate::key::dek::{DataEncryptionKey, Id as DekId};

#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
mod database;
#[cfg(feature = "memory-backend")]
mod memory;

#[cfg(any(feature = "mysql", feature = "postgres", feature = "sqlite"))]
pub use database::{Error as DatabaseError, SqlxBackend};
#[cfg(feature = "memory-backend")]
pub use memory::InMemoryBackend;

/// Common interface for DEK (Data Encryption Key) persistence.
#[async_trait::async_trait]
pub trait Storage: Send + Sync + 'static {
    /// Upserts (inserts or updates) a Data Encryption Key.
    ///
    /// If a DEK with the same ID already exists, it is updated;
    /// otherwise, a new DEK is inserted.
    async fn upsert_dek(&self, dek: &DataEncryptionKey) -> crate::Result<()>;

    /// Retrieves a Data Encryption Key by its ID.
    async fn get_dek(&self, id: &DekId) -> crate::Result<Option<DataEncryptionKey>>;
}
