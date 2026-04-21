use async_trait::async_trait;
use dashmap::DashMap;
use std::fmt::Debug;
use std::sync::Arc;

use crate::session::{IssuanceSession, IssuanceState};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Session not found: {0}")]
    NotFound(String),
    #[error("Invalid session state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },
    #[error("Session expired: {0}")]
    Expired(String),
    #[error("Session already in terminal state: {0}")]
    TerminalState(String),
}

#[async_trait]
pub trait SessionStore: Send + Sync + 'static + Debug {
    async fn insert(&self, session: IssuanceSession) -> Result<()>;
    async fn get(&self, id: &str) -> Result<IssuanceSession>;
    async fn update_state(&self, id: &str, new_state: IssuanceState) -> Result<()>;
    async fn set_tx_code(&self, id: &str, tx_code: String) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct InMemorySessionStore {
    sessions: Arc<DashMap<String, IssuanceSession>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn insert(&self, session: IssuanceSession) -> Result<()> {
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<IssuanceSession> {
        self.sessions
            .get(id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }

    async fn update_state(&self, id: &str, new_state: IssuanceState) -> Result<()> {
        let mut session = self.get(id).await?;

        if session.is_expired() {
            return Err(Error::Expired(id.to_string()));
        }

        session.state = new_state;
        self.sessions.insert(id.to_string(), session);
        Ok(())
    }

    async fn set_tx_code(&self, id: &str, tx_code: String) -> Result<()> {
        let mut session = self.get(id).await?;

        if session.is_expired() {
            return Err(Error::Expired(id.to_string()));
        }

        session.submitted_tx_code = Some(tx_code);
        self.sessions.insert(id.to_string(), session);
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.sessions
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }
}
