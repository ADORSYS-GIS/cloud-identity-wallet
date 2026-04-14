//! [`SessionStore`] trait — pluggable storage abstraction for issuance sessions.

use async_trait::async_trait;

use super::model::IssuanceSession;

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

/// Pluggable storage backend for [`IssuanceSession`]s.
///
/// Implementors MUST return [`SessionStoreError::Expired`] if `expires_at`
/// is in the past, even if the entry hasn't been evicted yet.
///
/// [`consume`][Self::consume] MUST be atomic (one caller wins).
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn create(&self, session: IssuanceSession) -> Result<()>;

    async fn get(&self, session_id: &str) -> Result<IssuanceSession>;

    /// Atomically retrieves and removes the session.
    async fn consume(&self, session_id: &str) -> Result<IssuanceSession>;

    async fn update(&self, session: &IssuanceSession) -> Result<()>;

    async fn delete(&self, session_id: &str) -> Result<()>;
}
