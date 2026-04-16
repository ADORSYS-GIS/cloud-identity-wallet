//! [`SessionManager`] — lifecycle manager wrapping a [`SessionStore`].

use std::{fmt::Debug, marker::PhantomData, sync::Arc};
use time::OffsetDateTime;

pub use super::store::SessionStoreError;
use super::store::{Result, SessionStore};

/// Generic session lifecycle manager.
#[derive(Clone)]
pub struct SessionManager<T, S>
where
    T: Send + Sync + 'static,
    S: SessionStore<T>,
{
    store: Arc<S>,
    _marker: PhantomData<T>,
}

impl<T, S> Debug for SessionManager<T, S>
where
    T: Send + Sync + 'static,
    S: SessionStore<T> + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("store", &self.store)
            .finish()
    }
}

impl<T, S> SessionManager<T, S>
where
    T: Send + Sync + 'static,
    S: SessionStore<T>,
{
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
            _marker: PhantomData,
        }
    }

    pub async fn create_session(
        &self,
        session_id: String,
        data: T,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        self.store.create(session_id, data, expires_at).await
    }

    pub async fn get_session(&self, session_id: &str) -> Result<T> {
        self.store.get(session_id).await
    }

    pub async fn update_session(&self, session_id: &str, data: T) -> Result<()> {
        self.store.update(session_id, data).await
    }

    /// Atomically retrieves and removes the session.
    pub async fn consume_session(&self, session_id: &str) -> Result<T> {
        self.store.consume(session_id).await
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id).await
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::server::session::memory::InMemorySessionStore;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockSession {
        id: String,
        data: String,
    }

    fn make_manager() -> SessionManager<MockSession, InMemorySessionStore<MockSession>> {
        SessionManager::new(InMemorySessionStore::new())
    }

    #[tokio::test]
    async fn create_and_get() {
        let mgr = make_manager();
        let session = MockSession {
            id: "test-id".to_string(),
            data: "some payload".to_string(),
        };

        mgr.create_session(
            session.id.clone(),
            session.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(15),
        )
        .await
        .unwrap();

        let found = mgr.get_session(&session.id).await.unwrap();
        assert_eq!(found, session);
    }

    #[tokio::test]
    async fn update_and_verify() {
        let mgr = make_manager();
        let mut session = MockSession {
            id: "test-id".to_string(),
            data: "initial".to_string(),
        };

        mgr.create_session(
            session.id.clone(),
            session.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(15),
        )
        .await
        .unwrap();

        session.data = "updated".to_string();
        mgr.update_session(&session.id, session.clone())
            .await
            .unwrap();

        let found = mgr.get_session(&session.id).await.unwrap();
        assert_eq!(found.data, "updated");
    }

    #[tokio::test]
    async fn consume_removes_session() {
        let mgr = make_manager();
        let session = MockSession {
            id: "test-id".to_string(),
            data: "payload".to_string(),
        };

        mgr.create_session(
            session.id.clone(),
            session.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(15),
        )
        .await
        .unwrap();

        mgr.consume_session(&session.id).await.unwrap();

        let err = mgr.get_session(&session.id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }
}
