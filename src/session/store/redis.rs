use std::time::Duration;

use redis::{AsyncCommands, ExistenceCheck, SetExpiry, SetOptions, aio::ConnectionManager};

use crate::session::{Id, Result, SessionError, SessionStore};

const DEFAULT_PREFIX: &str = "sessions";
const DEFAULT_TTL: Duration = Duration::from_mins(15);

/// A Redis-based session store.
///
/// This store uses Redis to persist session data with TTL support.
/// Sessions are stored with a key format: `{prefix}:{session_id}`.
/// By default, the prefix is "sessions" and the TTL is 15 minutes.
#[derive(Debug, Clone)]
pub struct RedisSession {
    conn: ConnectionManager,
    prefix: String,
    ttl: Duration,
}

impl RedisSession {
    /// Create a new Redis session manager from a connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_string(),
            ttl: DEFAULT_TTL,
        }
    }

    /// Overrides the default prefix for all session keys in this store.
    ///
    /// The default prefix is `"session"`.
    pub fn with_prefix(self, prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            ..self
        }
    }

    /// Overrides the default session TTL.
    ///
    /// The default TTL is 15 minutes.
    pub fn with_ttl(self, ttl: Duration) -> Self {
        assert!(
            ttl > Duration::ZERO,
            "session TTL must be greater than zero"
        );
        Self { ttl, ..self }
    }

    fn key(&self, id: &[u8]) -> Box<[u8]> {
        let mut key = Vec::with_capacity(self.prefix.len() + id.len());
        key.extend_from_slice(self.prefix.as_bytes());
        key.extend_from_slice(id);
        key.into_boxed_slice()
    }
}

#[async_trait::async_trait]
impl SessionStore for RedisSession {
    async fn upsert<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Into<Id> + Send + Sync,
        V: serde::Serialize + Send + Sync,
    {
        let encoded_value = postcard::to_allocvec(value)?;
        let key = self.key(key.into().as_bytes());
        let ttl_ms = self.ttl.as_millis().try_into().unwrap_or(u64::MAX);

        loop {
            let mut conn = self.conn.clone();
            let options = SetOptions::default()
                .conditional_set(ExistenceCheck::XX)
                .with_expiration(SetExpiry::KEEPTTL);
            let updated: Option<String> = conn.set_options(&key, &encoded_value, options).await?;

            if updated.is_some() {
                return Ok(());
            }

            let options = SetOptions::default()
                .conditional_set(ExistenceCheck::NX)
                .with_expiration(SetExpiry::PX(ttl_ms));
            let inserted: Option<String> = conn.set_options(&key, &encoded_value, options).await?;

            if inserted.is_some() {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    }

    async fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync,
    {
        let mut conn = self.conn.clone();
        let key = self.key(key.into().as_bytes());
        let value: Option<Vec<u8>> = conn.get(&key).await?;

        if let Some(v) = value {
            Ok(Some(postcard::from_bytes(&v)?))
        } else {
            Ok(None)
        }
    }

    async fn exists<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<bool> {
        let key = key.into();
        let mut conn = self.conn.clone();
        conn.exists(self.key(key.as_bytes()))
            .await
            .map_err(SessionError::from)
    }

    async fn consume<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync,
    {
        let key = key.into();
        let mut conn = self.conn.clone();
        let value: Option<Vec<u8>> = conn.get_del(self.key(key.as_bytes())).await?;

        if let Some(v) = value {
            Ok(Some(postcard::from_bytes(&v)?))
        } else {
            Ok(None)
        }
    }

    async fn remove<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<()> {
        let key = key.into();
        let mut conn = self.conn.clone();
        let _: usize = conn.del(self.key(key.as_bytes())).await?;
        Ok(())
    }
}

impl From<redis::RedisError> for SessionError {
    fn from(err: redis::RedisError) -> Self {
        SessionError::Store(Box::new(err))
    }
}
