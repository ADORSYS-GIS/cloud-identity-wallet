use dashmap::DashMap;
use time::OffsetDateTime;
use uuid::Uuid;
use crate::server::session::{IssuanceSession, SessionError};

pub struct MemorySessionStore {
    sessions: DashMap<String, IssuanceSession>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub async fn create(&self, session: IssuanceSession) -> Result<(), SessionError> {
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    pub async fn get(&self, id: &str, tenant_id: Uuid) -> Result<Option<IssuanceSession>, SessionError> {
        let Some(session) = self.sessions.get(id).map(|r| r.clone()) else {
            return Ok(None);
        };

        if OffsetDateTime::now_utc() >= session.expires_at {
            self.sessions.remove(id);
            return Ok(None);
        }

        if session.tenant_id != tenant_id {
            return Ok(None);
        }

        Ok(Some(session))
    }

    pub async fn update(&self, session: IssuanceSession) -> Result<(), SessionError> {
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<(), SessionError> {
        self.sessions.remove(id);
        Ok(())
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}
