#![cfg(feature = "memory-session")]

use async_trait::async_trait;
use dashmap::DashMap;
use time::UtcDateTime;
use uuid::Uuid;

use crate::errors::Result;
use crate::issuance::session::{IssuanceSession, store::SessionStore};

pub struct MemorySessionStore {
    sessions: DashMap<String, IssuanceSession>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn create(&self, session: IssuanceSession) -> Result<()> {
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn get(&self, id: &str, tenant_id: Uuid) -> Result<Option<IssuanceSession>> {
        let Some(session) = self.sessions.get(id).map(|r| r.clone()) else {
            return Ok(None);
        };

        if UtcDateTime::now() >= session.expires_at {
            self.sessions.remove(id);
            return Ok(None);
        }

        if session.tenant_id != tenant_id {
            return Ok(None);
        }

        Ok(Some(session))
    }

    async fn update(&self, session: IssuanceSession) -> Result<()> {
        self.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.sessions.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::credential_offer::CredentialOffer;
    use crate::issuance::session::{FlowType, IssuanceSession, IssuanceState, transition};

    fn make_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".into(),
            credential_configuration_ids: vec!["TestCredential".into()],
            grants: None,
        }
    }

    fn make_session() -> IssuanceSession {
        IssuanceSession::new(Uuid::new_v4(), make_offer(), FlowType::AuthorizationCode).unwrap()
    }

    #[tokio::test]
    async fn create_and_get_roundtrip() {
        let store = MemorySessionStore::new();
        let session = make_session();
        let id = session.id.clone();
        let tenant_id = session.tenant_id;

        store.create(session.clone()).await.unwrap();

        let fetched = store.get(&id, tenant_id).await.unwrap().unwrap();
        assert_eq!(fetched.id, session.id);
        assert_eq!(fetched.tenant_id, session.tenant_id);
        assert_eq!(fetched.state, session.state);
    }

    #[tokio::test]
    async fn expired_session_returns_none() {
        let store = MemorySessionStore::new();
        let mut session = make_session();
        session.expires_at = UtcDateTime::now() - time::Duration::seconds(1);
        let id = session.id.clone();
        let tenant_id = session.tenant_id;

        store.create(session).await.unwrap();

        let result = store.get(&id, tenant_id).await.unwrap();
        assert!(result.is_none(), "expired session must return None");
    }

    #[tokio::test]
    async fn wrong_tenant_returns_none() {
        let store = MemorySessionStore::new();
        let session = make_session();
        let id = session.id.clone();

        store.create(session).await.unwrap();

        let other_tenant = Uuid::new_v4();
        let result = store.get(&id, other_tenant).await.unwrap();
        assert!(result.is_none(), "wrong tenant must return None");
    }

    #[tokio::test]
    async fn update_persists_new_state() {
        let store = MemorySessionStore::new();
        let session = make_session();
        let id = session.id.clone();
        let tenant_id = session.tenant_id;

        store.create(session.clone()).await.unwrap();

        let mut updated = session;
        transition(&mut updated, IssuanceState::Processing).unwrap();
        store.update(updated).await.unwrap();

        let fetched = store.get(&id, tenant_id).await.unwrap().unwrap();
        assert_eq!(fetched.state, IssuanceState::Processing);
    }

    #[tokio::test]
    async fn delete_removes_session() {
        let store = MemorySessionStore::new();
        let session = make_session();
        let id = session.id.clone();
        let tenant_id = session.tenant_id;

        store.create(session).await.unwrap();
        store.delete(&id).await.unwrap();

        let result = store.get(&id, tenant_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn missing_session_returns_none() {
        let store = MemorySessionStore::new();
        let result = store.get("ses_doesnotexist", Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }
}
