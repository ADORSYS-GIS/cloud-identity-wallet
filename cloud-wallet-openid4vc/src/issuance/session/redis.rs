#![cfg(feature = "redis-session")]

use async_trait::async_trait;
use redis::AsyncCommands;
use time::UtcDateTime;
use uuid::Uuid;

use crate::errors::{Error, ErrorKind, Result};
use crate::issuance::session::{IssuanceSession, store::SessionStore};

const SESSION_TTL_SECS: u64 = 900;

fn session_key(id: &str) -> String {
    format!("issuance_session:{id}")
}

pub struct RedisSessionStore {
    client: redis::Client,
}

impl RedisSessionStore {
    pub fn new(client: redis::Client) -> Self {
        Self { client }
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(&self, session: IssuanceSession) -> Result<()> {
        let key = session_key(&session.id);
        let bytes = postcard::to_allocvec(&session)
            .map_err(|e| Error::message(ErrorKind::Other, format!("serialize session: {e}")))?;

        let mut conn = self.connection().await?;
        conn.set_ex::<_, _, ()>(&key, bytes.as_slice(), SESSION_TTL_SECS)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(())
    }

    async fn get(&self, id: &str, tenant_id: Uuid) -> Result<Option<IssuanceSession>> {
        let key = session_key(id);
        let mut conn = self.connection().await?;

        let bytes: Option<Vec<u8>> = conn
            .get(&key)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let Some(bytes) = bytes else {
            return Ok(None);
        };

        let session: IssuanceSession = postcard::from_bytes(&bytes)
            .map_err(|e| Error::message(ErrorKind::Other, format!("deserialize session: {e}")))?;

        if UtcDateTime::now() >= session.expires_at {
            return Ok(None);
        }

        if session.tenant_id != tenant_id {
            return Ok(None);
        }

        Ok(Some(session))
    }

    async fn update(&self, session: IssuanceSession) -> Result<()> {
        let key = session_key(&session.id);
        let bytes = postcard::to_allocvec(&session)
            .map_err(|e| Error::message(ErrorKind::Other, format!("serialize session: {e}")))?;

        let mut conn = self.connection().await?;
        conn.set_ex::<_, _, ()>(&key, bytes.as_slice(), SESSION_TTL_SECS)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let key = session_key(id);
        let mut conn = self.connection().await?;
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        Ok(())
    }
}
