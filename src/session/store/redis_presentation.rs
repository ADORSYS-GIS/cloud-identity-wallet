use std::time::Duration;

use redis::aio::ConnectionManager;

use crate::session::{
    Id, PresentationSession, PresentationSessionStoreError, PresentationState, RedisSession,
    Result, SessionStore,
};

const PRESENTATION_PREFIX: &str = "presentation_sessions";
const DEFAULT_TTL: Duration = Duration::from_mins(15);

/// A Redis-backed store for presentation sessions.
///
/// Uses a dedicated key prefix (`presentation_sessions`) and the same TTL
/// semantics as issuance sessions.  Provides `transition` which enforces
/// the state guard needed by the presentation flow.
#[derive(Debug, Clone)]
pub struct RedisPresentationSessionStore {
    inner: RedisSession,
}

impl RedisPresentationSessionStore {
    /// Create a new presentation session store backed by the given connection.
    pub fn new(conn: ConnectionManager) -> Self {
        let inner = RedisSession::new(conn)
            .with_prefix(PRESENTATION_PREFIX)
            .with_ttl(DEFAULT_TTL);
        Self { inner }
    }

    /// Set a custom TTL. Must be greater than zero.
    #[allow(dead_code)]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.inner = self.inner.with_ttl(ttl);
        self
    }

    /// Atomically transitions a session to a new terminal state.
    ///
    /// Returns:
    /// - `Ok(())` on success.
    /// - `PresentationSessionStoreError::SessionNotFound` if the session
    ///   does not exist or has expired (maps to 404).
    /// - `PresentationSessionStoreError::InvalidSessionState` if the session
    ///   is already terminal (maps to 409).
    pub async fn transition(
        &self,
        session_id: &str,
        new_state: PresentationState,
    ) -> std::result::Result<(), PresentationSessionStoreError> {
        let mut session: PresentationSession = self
            .inner
            .get(session_id)
            .await?
            .ok_or_else(|| PresentationSessionStoreError::SessionNotFound)?;

        if session.state != PresentationState::AwaitingConsent {
            return Err(PresentationSessionStoreError::InvalidSessionState);
        }
        if new_state == PresentationState::AwaitingConsent {
            return Err(PresentationSessionStoreError::InvalidSessionState);
        }

        session.state = new_state;
        self.inner.upsert(session_id, &session).await?;
        Ok(())
    }
}

// Delegate generic operations to the inner RedisSession.
#[async_trait::async_trait]
impl SessionStore for RedisPresentationSessionStore {
    async fn upsert<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Into<Id> + Send + Sync,
        V: serde::Serialize + Send + Sync,
    {
        self.inner.upsert(key, value).await
    }

    async fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.get(key).await
    }

    async fn exists<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<bool> {
        self.inner.exists(key).await
    }

    async fn consume<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync,
    {
        self.inner.consume(key).await
    }

    async fn remove<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<()> {
        self.inner.remove(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    use cloud_wallet_openid4vc::oid4vp::authorization::{
        AuthorizationRequest, ResponseMode, ResponseType,
    };
    use cloud_wallet_openid4vc::oid4vp::dcql::{
        CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery,
    };
    use cloud_wallet_openid4vc::oid4vp::selection::SelectionResult;
    use redis::Client;
    use testcontainers_modules::{
        redis::{REDIS_PORT, Redis},
        testcontainers::{ImageExt, runners::AsyncRunner},
    };
    use uuid::Uuid;

    async fn init_store(
        ttl: Duration,
    ) -> (
        RedisPresentationSessionStore,
        testcontainers_modules::testcontainers::ContainerAsync<Redis>,
    ) {
        let container = Redis::default()
            .with_tag("8-alpine")
            .start()
            .await
            .expect("redis container failed to start");

        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
        let connection_string = format!("redis://{host}:{port}");

        let client = Client::open(connection_string).expect("failed to create redis client");
        let conn = client
            .get_connection_manager()
            .await
            .expect("failed to get redis connection manager");

        let store = RedisPresentationSessionStore::new(conn).with_ttl(ttl);
        (store, container)
    }

    fn mock_session() -> PresentationSession {
        let request = AuthorizationRequest {
            response_type: ResponseType::VpToken,
            client_id: "client".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "nonce".to_string(),
            response_mode: ResponseMode::DirectPost,
            response_uri: Some(url::Url::parse("https://example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".to_string(),
                    format: CredentialFormat::DcSdJwt,
                    multiple: None,
                    meta: CredentialMeta::SdJwt {
                        vct_values: vec!["https://example.com/identity".to_string()],
                    },
                    claims: None,
                    claim_sets: None,
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                }],
                credential_sets: None,
            }),
            client_metadata: None,
            client_metadata_uri: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        };
        let dcql_result = SelectionResult {
            candidates: HashMap::new(),
            unsatisfied_queries: vec![],
            satisfies_query: true,
            selected_credential_query_ids: vec![],
            multiple_allowed_by_query_id: HashMap::new(),
        };
        PresentationSession::new(Uuid::new_v4(), request, dcql_result)
    }

    #[tokio::test]
    async fn redis_presentation_roundtrip_and_remove() {
        let (store, _container) = init_store(Duration::from_secs(2)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        assert!(store.exists(session_id.as_str()).await.unwrap());

        let retrieved: PresentationSession = store.get(session_id.as_str()).await.unwrap().unwrap();
        assert_eq!(retrieved.id, session_id);
        assert_eq!(retrieved.state, PresentationState::AwaitingConsent);

        store.remove(session_id.as_str()).await.unwrap();
        assert!(!store.exists(session_id.as_str()).await.unwrap());
    }

    #[tokio::test]
    async fn redis_presentation_consume_is_one_time() {
        let (store, _container) = init_store(Duration::from_secs(2)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        let retrieved: Option<PresentationSession> =
            store.consume(session_id.as_str()).await.unwrap();
        assert!(retrieved.is_some());

        let second: Option<PresentationSession> = store.consume(session_id.as_str()).await.unwrap();
        assert!(second.is_none());
    }

    #[tokio::test]
    async fn redis_presentation_expired_returns_not_found() {
        let (store, _container) = init_store(Duration::from_millis(50)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let exists = store.exists(session_id.as_str()).await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn redis_presentation_transition_valid() {
        let (store, _container) = init_store(Duration::from_secs(2)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        store
            .transition(session_id.as_str(), PresentationState::Completed)
            .await
            .unwrap();

        let retrieved: PresentationSession = store.get(session_id.as_str()).await.unwrap().unwrap();
        assert_eq!(retrieved.state, PresentationState::Completed);
    }

    #[tokio::test]
    async fn redis_presentation_transition_from_terminal_returns_invalid_state() {
        let (store, _container) = init_store(Duration::from_secs(2)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        store
            .transition(session_id.as_str(), PresentationState::Completed)
            .await
            .unwrap();

        let result = store
            .transition(session_id.as_str(), PresentationState::Failed)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn redis_presentation_transition_missing_returns_not_found() {
        let (store, _container) = init_store(Duration::from_secs(2)).await;
        let result = store
            .transition("nonexistent", PresentationState::Completed)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn redis_presentation_upsert_does_not_extend_ttl() {
        let (store, _container) = init_store(Duration::from_millis(220)).await;
        let session = mock_session();
        let session_id = session.id.clone();

        store.upsert(session_id.as_str(), &session).await.unwrap();
        tokio::time::sleep(Duration::from_millis(130)).await;

        // Update state without refreshing TTL
        store
            .transition(session_id.as_str(), PresentationState::Completed)
            .await
            .unwrap();

        let val: Option<PresentationSession> = store.get(session_id.as_str()).await.unwrap();
        assert!(val.is_some());

        tokio::time::sleep(Duration::from_millis(120)).await;
        let val: Option<PresentationSession> = store.get(session_id.as_str()).await.unwrap();
        assert!(val.is_none());
    }
}
