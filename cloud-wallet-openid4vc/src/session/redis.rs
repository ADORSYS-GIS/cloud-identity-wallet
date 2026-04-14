//! Redis-backed [`SessionStore`] implementation.
//!
//! Sessions are stored under `session:{session_id}` as JSON.

use std::time::Duration;

use async_trait::async_trait;
use redis::{AsyncCommands, Script, aio::ConnectionManager};

use super::{
    model::IssuanceSession,
    store::{Result, SessionStore, SessionStoreError},
};

const KEY_PREFIX: &str = "session:";

/// Redis session store.
#[derive(Clone)]
pub struct RedisSessionStore {
    conn: ConnectionManager,
}

impl std::fmt::Debug for RedisSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisSessionStore").finish_non_exhaustive()
    }
}

impl RedisSessionStore {
    pub async fn new(client: redis::Client) -> std::result::Result<Self, redis::RedisError> {
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    fn key(session_id: &str) -> String {
        format!("{KEY_PREFIX}{session_id}")
    }

    fn serialize(session: &IssuanceSession) -> Result<String> {
        serde_json::to_string(session).map_err(|e| SessionStoreError::Serialization(e.to_string()))
    }

    fn deserialize(data: &str, session_id: &str) -> Result<IssuanceSession> {
        serde_json::from_str(data).map_err(|e| {
            SessionStoreError::Backend(format!("failed to deserialize session {session_id}: {e}"))
        })
    }

    fn remaining_ttl(session: &IssuanceSession) -> Duration {
        let now = time::UtcDateTime::now();
        if session.expires_at <= now {
            Duration::ZERO
        } else {
            let secs = (session.expires_at - now).whole_seconds().max(0) as u64;
            Duration::from_secs(secs)
        }
    }
}

/// Lua fallback for `GETDEL` on Redis < 6.2.
const GETDEL_SCRIPT: &str = r#"
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
"#;

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(&self, session: IssuanceSession) -> Result<()> {
        let key = Self::key(&session.session_id);
        let value = Self::serialize(&session)?;
        let ttl = Self::remaining_ttl(&session);

        if ttl == Duration::ZERO {
            return Ok(());
        }

        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&key, value, ttl.as_secs())
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<IssuanceSession> {
        let key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let data: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        let data = data.ok_or_else(|| SessionStoreError::NotFound {
            session_id: session_id.to_string(),
        })?;

        let session = Self::deserialize(&data, session_id)?;

        if session.is_expired() {
            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| SessionStoreError::Backend(e.to_string()))?;
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(session)
    }

    async fn consume(&self, session_id: &str) -> Result<IssuanceSession> {
        let key = Self::key(session_id);
        let mut conn = self.conn.clone();

        let data: Option<String> = match redis::cmd("GETDEL")
            .arg(&key)
            .query_async::<Option<String>>(&mut conn)
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

        let session = Self::deserialize(&data, session_id)?;

        if session.is_expired() {
            return Err(SessionStoreError::Expired {
                session_id: session_id.to_string(),
            });
        }

        Ok(session)
    }

    async fn update(&self, session: &IssuanceSession) -> Result<()> {
        let key = Self::key(&session.session_id);
        let value = Self::serialize(session)?;
        let ttl = Self::remaining_ttl(session);

        let mut conn = self.conn.clone();

        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .arg("EX")
            .arg(ttl.as_secs().max(1))
            .arg("XX")
            .query_async(&mut conn)
            .await
            .map_err(|e| SessionStoreError::Backend(e.to_string()))?;

        if result.is_none() {
            return Err(SessionStoreError::NotFound {
                session_id: session.session_id.clone(),
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
