//! In-memory [`SessionStore`] implementation.

use async_trait::async_trait;
use dashmap::DashMap;
use std::{fmt::Debug, marker::PhantomData, sync::Arc};
use time::OffsetDateTime;

use super::store::{Result, SessionStore, SessionStoreError};

#[derive(Clone, Debug)]
struct SessionEntry<T> {
    data: T,
    expires_at: OffsetDateTime,
}

pub struct InMemorySessionStore<T> {
    sessions: Arc<DashMap<String, SessionEntry<T>>>,
    _marker: PhantomData<T>,
}

impl<T> Default for InMemorySessionStore<T> {
    fn default() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            _marker: PhantomData,
        }
    }
}

impl<T> Clone for InMemorySessionStore<T> {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
            _marker: PhantomData,
        }
    }
}

impl<T> Debug for InMemorySessionStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySessionStore")
            .field("len", &self.sessions.len())
            .finish()
    }
}

impl<T> InMemorySessionStore<T> {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl<T> SessionStore<T> for InMemorySessionStore<T>
where
    T: Clone + Send + Sync + 'static,
{
    async fn create(
        &self,
        session_id: String,
        session: T,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        self.sessions.insert(
            session_id,
            SessionEntry {
                data: session,
                expires_at,
            },
        );
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<T> {
        let entry = self
            .sessions
            .get(session_id)
            .ok_or_else(|| SessionStoreError::NotFound {
                session_id: session_id.to_string(),
            })?;

        let val = entry.value();
        if OffsetDateTime::now_utc() >= val.expires_at {
            drop(entry);
            self.sessions.remove(session_id);
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(entry.data.clone())
    }

    async fn consume(&self, session_id: &str) -> Result<T> {
        let (_, entry) =
            self.sessions
                .remove(session_id)
                .ok_or_else(|| SessionStoreError::NotFound {
                    session_id: session_id.to_string(),
                })?;

        if OffsetDateTime::now_utc() >= entry.expires_at {
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(entry.data)
    }

    async fn update(&self, session_id: &str, session: T) -> Result<()> {
        let mut entry =
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| SessionStoreError::NotFound {
                    session_id: session_id.to_string(),
                })?;

        entry.value_mut().data = session;
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
    use super::*;
    use time::Duration;
    use tokio::task::JoinSet;

    #[tokio::test]
    async fn create_and_get() {
        let store = InMemorySessionStore::<String>::new();
        let id = "test".to_string();
        let data = "data".to_string();
        let expiry = OffsetDateTime::now_utc() + Duration::minutes(1);

        store
            .create(id.clone(), data.clone(), expiry)
            .await
            .unwrap();
        let found = store.get(&id).await.unwrap();
        assert_eq!(found, data);
    }

    #[tokio::test]
    async fn expired_is_removed() {
        let store = InMemorySessionStore::<String>::new();
        let id = "test".to_string();
        let expiry = OffsetDateTime::now_utc() - Duration::minutes(1);

        store
            .create(id.clone(), "data".to_string(), expiry)
            .await
            .unwrap();
        let err = store.get(&id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::Expired { .. }));
    }

    #[tokio::test]
    async fn concurrent_consume() {
        let store = Arc::new(InMemorySessionStore::<String>::new());
        let id = "test".to_string();
        store
            .create(
                id.clone(),
                "data".to_string(),
                OffsetDateTime::now_utc() + Duration::minutes(1),
            )
            .await
            .unwrap();

        let mut set = JoinSet::new();
        for _ in 0..10 {
            let store = Arc::clone(&store);
            let id = id.clone();
            set.spawn(async move { store.consume(&id).await });
        }

        let mut successes = 0;
        while let Some(res) = set.join_next().await {
            if res.unwrap().is_ok() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1);
    }
}
