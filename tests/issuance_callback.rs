//! Integration tests for GET /api/v1/issuance/callback

pub mod utils;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::issuance::{
            FlowType, IssuanceEngine, IssuanceError, IssuanceEvent, IssuanceStep, IssuanceTask,
        },
        ports::{IssuanceEventSubscriber, IssuanceTaskQueue},
        service::Service,
    },
    outbound::{
        MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTenantRepo,
    },
    server::Server,
    session::{IssuanceSession, IssuanceState, MemorySession, SessionStore},
};
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};
use futures::StreamExt;
use reqwest::Client;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
struct RecordingTaskQueue {
    pushed: Arc<Mutex<Vec<IssuanceTask>>>,
}

#[async_trait]
impl IssuanceTaskQueue for RecordingTaskQueue {
    async fn push(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        self.pushed.lock().unwrap().push(task.clone());
        Ok(())
    }

    async fn pop(&self) -> Result<Option<IssuanceTask>, IssuanceError> {
        Ok(None)
    }

    async fn ack(&self, _task: &IssuanceTask) -> Result<(), IssuanceError> {
        Ok(())
    }
}

struct CallbackTestApp {
    base_url: String,
    session_store: MemorySession,
    pushed_tasks: Arc<Mutex<Vec<IssuanceTask>>>,
    event_subscriber: MemoryEventSubscriber,
}

async fn spawn_callback_test_app(session_store: MemorySession) -> CallbackTestApp {
    let mut config = Config::load().unwrap();
    config.server.host = "localhost".to_owned();
    config.server.port = 0;
    config.oid4vci.use_system_proxy = false;

    let queue = RecordingTaskQueue::default();
    let pushed_tasks = queue.pushed.clone();
    let publisher = MemoryEventPublisher::new(16);
    let event_subscriber = MemoryEventSubscriber::new(&publisher);
    let tenant_repo = MemoryTenantRepo::new();
    let client_config = Oid4vciClientConfig::new(
        "wallet-client",
        Url::parse("https://wallet.example.com/api/v1/issuance/callback").unwrap(),
    )
    .timeout(Duration::from_secs(60))
    .accept_untrusted_hosts(true);

    let client = Oid4vciClient::new(client_config).unwrap();
    let engine = IssuanceEngine::new(
        client,
        queue,
        publisher,
        MemoryCredentialRepo::new(),
        tenant_repo.clone(),
        &session_store,
    );
    let service = Service::new(session_store.clone(), tenant_repo, engine);
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();

    tokio::spawn(server.run());

    CallbackTestApp {
        base_url: format!("http://{}:{port}", config.server.host),
        session_store,
        pushed_tasks,
        event_subscriber,
    }
}

fn mock_session(session_id: &str, state: IssuanceState) -> IssuanceSession {
    let context = serde_json::from_value(serde_json::json!({
        "offer": {
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_id"],
            "grants": {
                "authorization_code": {
                    "issuer_state": session_id
                }
            }
        },
        "issuer_metadata": {
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "test_id": {
                    "format": "dc+sd-jwt",
                    "vct": "https://credentials.example.com/test"
                }
            }
        },
        "as_metadata": {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/authorize",
            "token_endpoint": "https://10.255.255.1/token",
            "response_types_supported": ["code"]
        },
        "flow": {
            "AuthorizationCode": {
                "issuer_state": session_id
            }
        },
    }))
    .unwrap();

    let mut session = IssuanceSession::new(Uuid::new_v4(), context, FlowType::AuthorizationCode);
    session.id = session_id.to_owned();
    session.state = state;
    session.selected_config_ids = vec!["test_id".to_owned()];
    session.code_verifier = Some("pkce-verifier".to_owned());
    session
}

#[tokio::test]
async fn valid_callback_transitions_session_to_processing_and_enqueues_task() {
    let session_id = "ses_callback_success";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingAuthorization);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_callback_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .get(format!(
            "{}/api/v1/issuance/callback?code=auth-code&state={session_id}",
            app.base_url
        ))
        .send()
        .await
        .expect("failed to send callback request");

    assert_eq!(response.status(), 200);
    assert!(response.bytes().await.unwrap().is_empty());

    let session: IssuanceSession = app.session_store.get(session_id).await.unwrap().unwrap();
    assert_eq!(session.state, IssuanceState::Processing);

    let tasks = app.pushed_tasks.lock().unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].session_id, session_id);
    assert_eq!(tasks[0].authorization_code.as_deref(), Some("auth-code"));
}

#[tokio::test]
async fn error_callback_fails_emits_event_and_discards_session() {
    let session_id = "ses_callback_error";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingAuthorization);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_callback_test_app(session_store).await;
    let mut stream = app.event_subscriber.subscribe(session_id).await.unwrap();
    let client = Client::new();

    let response = client
        .get(format!(
            "{}/api/v1/issuance/callback?error=access_denied&error_description=No+thanks&state={session_id}",
            app.base_url
        ))
        .send()
        .await
        .expect("failed to send callback request");

    assert_eq!(response.status(), 200);
    assert!(response.bytes().await.unwrap().is_empty());

    let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("timed out waiting for failed event")
        .expect("event stream ended");
    match event {
        IssuanceEvent::Failed(failed) => {
            assert_eq!(failed.session_id, session_id);
            assert_eq!(failed.error, "access_denied");
            assert_eq!(failed.error_description.as_deref(), Some("No thanks"));
            assert_eq!(failed.step, IssuanceStep::Authorization);
        }
        other => panic!("expected failed event, got {other:?}"),
    }

    let session: Option<IssuanceSession> = app.session_store.get(session_id).await.unwrap();
    assert!(session.is_none());
}

#[tokio::test]
async fn expired_state_returns_bad_request() {
    let session_id = "ses_expired_callback";
    let session_store = MemorySession::new(Duration::from_millis(30));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingAuthorization);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let app = spawn_callback_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .get(format!(
            "{}/api/v1/issuance/callback?code=auth-code&state={session_id}",
            app.base_url
        ))
        .send()
        .await
        .expect("failed to send callback request");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn non_authorization_state_returns_bad_request() {
    let session_id = "ses_wrong_state_callback";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingConsent);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_callback_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .get(format!(
            "{}/api/v1/issuance/callback?code=auth-code&state={session_id}",
            app.base_url
        ))
        .send()
        .await
        .expect("failed to send callback request");

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["error"], "invalid_request");
}
