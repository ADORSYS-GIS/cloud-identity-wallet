use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use cloud_identity_wallet::{
    domain::models::issuance::IssuanceEngine,
    domain::service::Service,
    outbound::{MemoryCredentialRepo, MemoryEventPublisher, MemoryTaskQueue, MemoryTenantRepo},
    server::{AppState, submit_consent},
    session::{FlowType, Id, IssuanceSession, SessionStore},
};
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciConfig, Oid4vciClient};
use dashmap::{DashMap, Entry};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

/// A JSON-based in-memory session store for testing.
///
/// This store uses JSON serialization instead of postcard to support
/// types like `serde_json::Value` which cannot be serialized with postcard.
#[derive(Debug, Clone)]
struct JsonMemorySession {
    entries: Arc<DashMap<Box<[u8]>, SessionEntry>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    value: Box<[u8]>,
    expires_at: Instant,
}

impl JsonMemorySession {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::default(),
            ttl,
        }
    }

    fn make_entry(&self, value: &[u8]) -> SessionEntry {
        SessionEntry {
            value: value.into(),
            expires_at: Instant::now() + self.ttl,
        }
    }

    fn is_expired(entry: &SessionEntry) -> bool {
        Instant::now() >= entry.expires_at
    }
}

impl Default for JsonMemorySession {
    fn default() -> Self {
        Self::new(Duration::from_secs(900))
    }
}

#[async_trait::async_trait]
impl SessionStore for JsonMemorySession {
    async fn upsert<K, V>(&self, key: K, value: &V) -> cloud_identity_wallet::session::Result<()>
    where
        K: Into<Id> + Send + Sync,
        V: serde::Serialize + Send + Sync,
    {
        let key = key.into();
        let value_bytes = serde_json::to_vec(value)
            .map_err(|e| cloud_identity_wallet::session::SessionError::Store(Box::new(e)))?;
        let key_bytes: Box<[u8]> = key.as_bytes().into();

        match self.entries.entry(key_bytes) {
            Entry::Occupied(mut occupied) => {
                if Self::is_expired(occupied.get()) {
                    occupied.insert(self.make_entry(&value_bytes));
                } else {
                    occupied.get_mut().value = value_bytes.into_boxed_slice();
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(self.make_entry(&value_bytes));
            }
        }
        Ok(())
    }

    async fn get<K, V>(&self, key: K) -> cloud_identity_wallet::session::Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: DeserializeOwned + Send + Sync,
    {
        let key = key.into();
        if let Some(entry) = self.entries.get(key.as_bytes()) {
            if Self::is_expired(&entry) {
                drop(entry);
                self.entries.remove(key.as_bytes());
                return Ok(None);
            }
            let item: V = serde_json::from_slice(&entry.value)
                .map_err(|e| cloud_identity_wallet::session::SessionError::Store(Box::new(e)))?;
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }

    async fn exists<K>(&self, key: K) -> cloud_identity_wallet::session::Result<bool>
    where
        K: Into<Id> + Send + Sync,
    {
        let key = key.into();
        if let Some(entry) = self.entries.get(key.as_bytes()) {
            if Self::is_expired(&entry) {
                drop(entry);
                self.entries.remove(key.as_bytes());
                Ok(false)
            } else {
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }

    async fn consume<K, V>(&self, key: K) -> cloud_identity_wallet::session::Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: DeserializeOwned + Send + Sync,
    {
        let key = key.into();
        if let Some((_, entry)) = self.entries.remove(key.as_bytes()) {
            if Self::is_expired(&entry) {
                return Ok(None);
            }
            let item: V = serde_json::from_slice(&entry.value)
                .map_err(|e| cloud_identity_wallet::session::SessionError::Store(Box::new(e)))?;
            Ok(Some(item))
        } else {
            Ok(None)
        }
    }

    async fn remove<K>(&self, key: K) -> cloud_identity_wallet::session::Result<()>
    where
        K: Into<Id> + Send + Sync,
    {
        let key = key.into();
        self.entries.remove(key.as_bytes());
        Ok(())
    }
}

fn create_test_state() -> AppState<JsonMemorySession> {
    let session_store = JsonMemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();

    let oid4vci_config = Oid4vciConfig::new(
        "test-wallet".to_string(),
        url::Url::parse("http://localhost:3000/api/v1/issuance/callback").unwrap(),
    )
    .accept_untrusted_hosts(true);
    let oid4vci_client = Oid4vciClient::new(oid4vci_config).unwrap();

    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let credential_repo = MemoryCredentialRepo::new();

    let issuance_engine = IssuanceEngine::new(
        oid4vci_client,
        task_queue,
        publisher,
        credential_repo,
        tenant_repo.clone(),
    );

    let service = Service::new(session_store, tenant_repo, issuance_engine);

    AppState {
        service: Arc::new(service),
    }
}

fn create_test_session(flow: FlowType) -> IssuanceSession {
    use cloud_wallet_openid4vc::issuance::credential_offer::CredentialOffer;
    use cloud_wallet_openid4vc::issuance::issuer_metadata::CredentialIssuerMetadata;
    use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;
    use cloud_wallet_openid4vc::issuance::client::{IssuanceFlow, ResolvedOfferContext};

    let offer: CredentialOffer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_credential_id"],
        "grants": {
            "authorization_code": {
                "issuer_state": "test_issuer_state"
            }
        }
    }))
    .unwrap();

    let issuer_metadata: CredentialIssuerMetadata = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "credential_configurations_supported": {}
    }))
    .unwrap();

    let as_metadata: AuthorizationServerMetadata = serde_json::from_value(json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token"
    }))
    .unwrap();

    let issuance_flow = match flow {
        FlowType::AuthorizationCode => IssuanceFlow::AuthorizationCode {
            issuer_state: Some("test_issuer_state".to_string()),
        },
        FlowType::PreAuthorizedCode => IssuanceFlow::PreAuthorizedCode {
            pre_authorized_code: "test_code".to_string(),
            tx_code: None,
        },
    };

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow: issuance_flow,
    };

    IssuanceSession::new(uuid::Uuid::new_v4(), context, flow)
}

#[tokio::test]
async fn test_consent_rejected() {
    let state = create_test_state();
    let session = create_test_session(FlowType::AuthorizationCode);
    let session_id = session.id.clone();
    state
        .service
        .session
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let app = axum::Router::new()
        .route(
            "/api/v1/issuance/{session_id}/consent",
            axum::routing::post(submit_consent),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": false}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["next_action"], "rejected");
}

#[tokio::test]
async fn test_consent_invalid_state() {
    let state = create_test_state();

    // Create a session and manually set it to a different state
    let mut session = create_test_session(FlowType::AuthorizationCode);
    session.state = cloud_identity_wallet::session::IssuanceState::Processing;
    let session_id = session.id.clone();
    state
        .service
        .session
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let app = axum::Router::new()
        .route(
            "/api/v1/issuance/{session_id}/consent",
            axum::routing::post(submit_consent),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}
