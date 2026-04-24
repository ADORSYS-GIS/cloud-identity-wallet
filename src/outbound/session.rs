use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;

use crate::domain::models::consent::SessionError;
use crate::domain::ports::SessionRepository;
use crate::session::IssuanceSession;

#[derive(Debug, Clone, Default)]
pub struct MemorySessionRepository {
    sessions: Arc<DashMap<String, IssuanceSession>>,
}

impl MemorySessionRepository {
    pub fn new() -> Self {
        Self {
            sessions: Arc::default(),
        }
    }
}

#[async_trait]
impl SessionRepository for MemorySessionRepository {
    async fn get(&self, session_id: &str) -> Result<Option<IssuanceSession>, SessionError> {
        Ok(self.sessions.get(session_id).map(|r| r.clone()))
    }

    async fn save(&self, session: &IssuanceSession) -> Result<(), SessionError> {
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}
