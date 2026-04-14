//! In-memory [`SessionStore`] implementation using [`dashmap::DashMap`].
//!
//! TTL is checked on read. For production workloads, use the Redis backend.

use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;

use super::{
    model::IssuanceSession,
    store::{Result, SessionStore, SessionStoreError},
};

/// In-memory session store.
#[derive(Clone, Default)]
pub struct InMemorySessionStore {
    sessions: Arc<DashMap<String, IssuanceSession>>,
}

impl std::fmt::Debug for InMemorySessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySessionStore")
            .field("len", &self.sessions.len())
            .finish()
    }
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(&self, session: IssuanceSession) -> Result<()> {
        self.sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<IssuanceSession> {
        let entry = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionStoreError::NotFound {
                session_id: session_id.to_string(),
            })?;

        let session = entry.value().clone();
        drop(entry);

        if session.is_expired() {
            self.sessions.remove(session_id);
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(session)
    }

    async fn consume(&self, session_id: &str) -> Result<IssuanceSession> {
        let (_, session) =
            self.sessions
                .remove(session_id)
                .ok_or_else(|| SessionStoreError::NotFound {
                    session_id: session_id.to_string(),
                })?;

        if session.is_expired() {
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(session)
    }

    async fn update(&self, session: &IssuanceSession) -> Result<()> {
        let mut entry = self.sessions.get_mut(&session.session_id).ok_or_else(|| {
            SessionStoreError::NotFound {
                session_id: session.session_id.clone(),
            }
        })?;

        *entry.value_mut() = session.clone();
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        self.sessions
            .remove(session_id)
            .ok_or_else(|| SessionStoreError::NotFound {
                session_id: session_id.to_string(),
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::task::JoinSet;
    use uuid::Uuid;

    use super::*;
    use crate::session::model::{DEFAULT_SESSION_TTL_SECS, IssuanceSessionState};

    fn sample_session() -> IssuanceSession {
        IssuanceSession::new(
            Uuid::new_v4(),
            "https://issuer.example".to_string(),
            vec!["eu.europa.ec.eudi.pid.1".to_string()],
            DEFAULT_SESSION_TTL_SECS,
        )
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let store = InMemorySessionStore::new();
        let session = sample_session();
        let id = session.session_id.clone();

        store.create(session.clone()).await.unwrap();

        let found = store.get(&id).await.unwrap();
        assert_eq!(found.session_id, session.session_id);
        assert_eq!(found.tenant_id, session.tenant_id);
        assert_eq!(found.credential_issuer, session.credential_issuer);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_not_found() {
        let store = InMemorySessionStore::new();
        let err = store.get("nonexistent-id").await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn get_expired_returns_expired_error() {
        let store = InMemorySessionStore::new();
        let session = IssuanceSession::new(
            Uuid::new_v4(),
            "https://issuer.example".to_string(),
            vec![],
            -1, // already in the past
        );
        let id = session.session_id.clone();
        store.create(session).await.unwrap();

        let err = store.get(&id).await.unwrap_err();
        assert!(
            matches!(err, SessionStoreError::Expired { .. }),
            "expected Expired, got {err:?}"
        );
    }

    #[tokio::test]
    async fn consume_removes_entry() {
        let store = InMemorySessionStore::new();
        let session = sample_session();
        let id = session.session_id.clone();
        store.create(session.clone()).await.unwrap();

        // First consume succeeds
        let consumed = store.consume(&id).await.unwrap();
        assert_eq!(consumed.session_id, session.session_id);

        // Second consume returns NotFound
        let err = store.consume(&id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn update_persists_state_change() {
        let store = InMemorySessionStore::new();
        let mut session = sample_session();
        let id = session.session_id.clone();
        store.create(session.clone()).await.unwrap();

        session.state = IssuanceSessionState::Completed;
        store.update(&session).await.unwrap();

        let found = store.get(&id).await.unwrap();
        assert_eq!(found.state, IssuanceSessionState::Completed);
    }

    #[tokio::test]
    async fn update_nonexistent_returns_not_found() {
        let store = InMemorySessionStore::new();
        let session = sample_session();
        let err = store.update(&session).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let store = InMemorySessionStore::new();
        let session = sample_session();
        let id = session.session_id.clone();
        store.create(session).await.unwrap();
        store.delete(&id).await.unwrap();

        let err = store.get(&id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let store = InMemorySessionStore::new();
        let err = store.delete("ghost-id").await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    /// Verifies that exactly one of many concurrent `consume` calls succeeds.
    #[tokio::test]
    async fn concurrent_consume_only_one_wins() {
        let store = Arc::new(InMemorySessionStore::new());
        let session = sample_session();
        let id = session.session_id.clone();
        store.create(session).await.unwrap();

        let mut set = JoinSet::new();
        for _ in 0..20 {
            let store = Arc::clone(&store);
            let id = id.clone();
            set.spawn(async move { store.consume(&id).await });
        }

        let mut successes = 0usize;
        while let Some(result) = set.join_next().await {
            if result.unwrap().is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1, "exactly one consume should succeed");
    }
}
