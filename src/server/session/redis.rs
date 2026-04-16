//! Redis-backed [`SessionStore`] implementation.

use async_trait::async_trait;
use redis::{AsyncCommands, Script, aio::ConnectionManager};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use time::OffsetDateTime;

use super::store::{Result, SessionStore, SessionStoreError};

const KEY_PREFIX: &str = "session:";

#[derive(Clone)]
pub struct RedisSessionStore<T> {
    conn: ConnectionManager,
    _marker: PhantomData<T>,
}

impl<T> std::fmt::Debug for RedisSessionStore<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisSessionStore").finish_non_exhaustive()
    }
}

impl<T> RedisSessionStore<T> {
    pub async fn new(client: redis::Client) -> std::result::Result<Self, redis::RedisError> {
        let conn = ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            _marker: PhantomData,
        })
    }

    fn key(session_id: &str) -> String {
        format!("{KEY_PREFIX}{session_id}")
    }

    fn encode(data: &T) -> Result<Vec<u8>>
    where
        T: Serialize,
    {
        postcard::to_stdvec(data).map_err(|e| SessionStoreError::Serialization(e.to_string()))
    }

    fn decode(data: &[u8], session_id: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        postcard::from_bytes(data).map_err(|e| {
            SessionStoreError::Backend(format!("failed to deserialize session {session_id}: {e}"))
        })
    }
}

const GETDEL_SCRIPT: &str = r#"
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
"#;

#[async_trait]
impl<T> SessionStore<T> for RedisSessionStore<T>
where
    T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static,
{
    async fn create(
        &self,
        session_id: String,
        session: T,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        let key = Self::key(&session_id);
        let value = Self::encode(&session)?;

        let now = OffsetDateTime::now_utc();
        let ttl_secs = (expires_at - now).whole_seconds().max(0) as u64;

        if ttl_secs == 0 {
            return Ok(());
        }

        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&key, value, ttl_secs)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<T> {
        let key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let data: Option<Vec<u8>> = conn
            .get(&key)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        let data = data.ok_or_else(|| SessionStoreError::NotFound {
            session_id: session_id.to_string(),
        })?;

        Self::decode(&data, session_id)
    }

    async fn consume(&self, session_id: &str) -> Result<T> {
        let key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let data: Option<Vec<u8>> = match redis::cmd("GETDEL")
            .arg(&key)
            .query_async::<Option<Vec<u8>>>(&mut conn)
            .await
        {
            Ok(v) => v,
            Err(_) => Script::new(GETDEL_SCRIPT)
                .key(&key)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| SessionStoreError::Backend(e.to_string()))?,
        };

        let data = data.ok_or_else(|| SessionStoreError::NotFound {
            session_id: session_id.to_string(),
        })?;

        Self::decode(&data, session_id)
    }

    async fn update(&self, session_id: &str, session: T) -> Result<()> {
        let key = Self::key(session_id);
        let value = Self::encode(&session)?;

        let mut conn = self.conn.clone();

        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .arg("KEEPTTL")
            .arg("XX")
            .query_async(&mut conn)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        if result.is_none() {
            return Err(SessionStoreError::NotFound {
                session_id: session_id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        let key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let deleted: i64 = conn
            .del(&key)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        if deleted == 0 {
            return Err(SessionStoreError::NotFound {
                session_id: session_id.to_string(),
            });
        }

        Ok(())
    }
}
