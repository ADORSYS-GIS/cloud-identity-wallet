//! [`SessionService`] wraps a [`SessionStore`] for application use.

use std::sync::Arc;

use uuid::Uuid;

pub use super::store::SessionStoreError;
use super::{
    model::{DEFAULT_SESSION_TTL_SECS, IssuanceSession},
    store::{Result, SessionStore},
};

/// Service façace for session management.
#[derive(Clone)]
pub struct SessionService {
    store: Arc<dyn SessionStore>,
    ttl_secs: i64,
}

impl std::fmt::Debug for SessionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionService")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

impl SessionService {
    pub fn new(store: impl SessionStore) -> Self {
        Self::with_ttl(store, DEFAULT_SESSION_TTL_SECS)
    }

    pub fn with_ttl(store: impl SessionStore, ttl_secs: i64) -> Self {
        Self {
            store: Arc::new(store),
            ttl_secs,
        }
    }

    pub async fn create_session(
        &self,
        tenant_id: Uuid,
        credential_issuer: String,
        credential_configuration_ids: Vec<String>,
    ) -> Result<IssuanceSession> {
        let session = IssuanceSession::new(
            tenant_id,
            credential_issuer,
            credential_configuration_ids,
            self.ttl_secs,
        );
        self.store.create(session.clone()).await?;
        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<IssuanceSession> {
        self.store.get(session_id).await
    }

    pub async fn update_session(&self, session: &IssuanceSession) -> Result<()> {
        self.store.update(session).await
    }

    pub async fn consume_session(&self, session_id: &str) -> Result<IssuanceSession> {
        self.store.consume(session_id).await
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id).await
    }
}

#[cfg(test)]
#[cfg(feature = "session-memory")]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::session::{
        memory::InMemorySessionStore, model::IssuanceSessionState, store::SessionStoreError,
    };

    fn make_service() -> SessionService {
        SessionService::new(InMemorySessionStore::new())
    }

    #[tokio::test]
    async fn create_and_get() {
        let svc = make_service();
        let tenant = Uuid::new_v4();

        let session = svc
            .create_session(
                tenant,
                "https://issuer.example".to_string(),
                vec!["eu.europa.ec.eudi.pid.1".to_string()],
            )
            .await
            .unwrap();

        let found = svc.get_session(&session.session_id).await.unwrap();
        assert_eq!(found.session_id, session.session_id);
        assert_eq!(found.state, IssuanceSessionState::AwaitingConsent);
    }

    #[tokio::test]
    async fn update_and_verify() {
        let svc = make_service();
        let mut session = svc
            .create_session(Uuid::new_v4(), "https://issuer.example".to_string(), vec![])
            .await
            .unwrap();

        session.state = IssuanceSessionState::Completed;
        svc.update_session(&session).await.unwrap();

        let found = svc.get_session(&session.session_id).await.unwrap();
        assert_eq!(found.state, IssuanceSessionState::Completed);
    }

    #[tokio::test]
    async fn consume_removes_session() {
        let svc = make_service();
        let session = svc
            .create_session(Uuid::new_v4(), "https://issuer.example".to_string(), vec![])
            .await
            .unwrap();
        let id = session.session_id.clone();

        svc.consume_session(&id).await.unwrap();

        let err = svc.get_session(&id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn delete_removes_session() {
        let svc = make_service();
        let session = svc
            .create_session(Uuid::new_v4(), "https://issuer.example".to_string(), vec![])
            .await
            .unwrap();
        let id = session.session_id.clone();

        svc.delete_session(&id).await.unwrap();

        let err = svc.get_session(&id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::NotFound { .. }));
    }

    #[tokio::test]
    async fn custom_ttl_is_applied() {
        let svc = SessionService::with_ttl(InMemorySessionStore::new(), -1);
        let session = svc
            .create_session(Uuid::new_v4(), "https://issuer.example".to_string(), vec![])
            .await
            .unwrap();

        let err = svc.get_session(&session.session_id).await.unwrap_err();
        assert!(matches!(err, SessionStoreError::Expired { .. }));
    }
}
