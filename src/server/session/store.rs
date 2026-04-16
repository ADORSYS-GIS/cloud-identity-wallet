//! [`SessionStore`] trait — pluggable storage abstraction for sessions.

use async_trait::async_trait;
use time::OffsetDateTime;

/// Errors for session store operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session not found: {session_id}")]
    NotFound { session_id: String },

    #[error("session expired: {session_id}")]
    Expired { session_id: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, SessionStoreError>;

/// Pluggable storage backend for sessions.
#[async_trait]
pub trait SessionStore<T>: Send + Sync + 'static
where
    T: Send + Sync + 'static,
{
    async fn create(
        &self,
        session_id: String,
        session: T,
        expires_at: OffsetDateTime,
    ) -> Result<()>;

    async fn get(&self, session_id: &str) -> Result<T>;

    /// Atomically retrieves and removes the session.
    async fn consume(&self, session_id: &str) -> Result<T>;

    async fn update(&self, session_id: &str, session: T) -> Result<()>;

    async fn delete(&self, session_id: &str) -> Result<()>;
}
