//! Integration tests for POST /api/v1/issuance/{session_id}/tx-code

pub mod utils;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::issuance::{FlowType, IssuanceEngine, IssuanceError, IssuanceTask},
        ports::IssuanceTaskQueue,
        service::Service,
    },
    outbound::{MemoryCredentialRepo, MemoryEventPublisher, MemoryTenantRepo},
    server::Server,
    session::{IssuanceSession, IssuanceState, MemorySession, SessionStore},
};
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use time::OffsetDateTime;
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

struct TxCodeTestApp {
    base_url: String,
    session_store: MemorySession,
    pushed_tasks: Arc<Mutex<Vec<IssuanceTask>>>,
    auth_token: String,
}

async fn spawn_tx_code_test_app(session_store: MemorySession) -> TxCodeTestApp {
    let mut config = Config::load().unwrap();
    config.server.host = "localhost".to_owned();
    config.server.port = 0;
    config.oid4vci.use_system_proxy = false;

    let queue = RecordingTaskQueue::default();
    let pushed_tasks = queue.pushed.clone();
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
        MemoryEventPublisher::new(16),
        MemoryCredentialRepo::new(),
        tenant_repo.clone(),
        &session_store,
    );
    let service = Service::new(session_store.clone(), tenant_repo, engine);
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();

    tokio::spawn(server.run());

    let auth_token = create_test_bearer_token(Uuid::new_v4());

    TxCodeTestApp {
        base_url: format!("http://{}:{port}", config.server.host),
        session_store,
        pushed_tasks,
        auth_token,
    }
}

fn create_test_keypair() -> (String, jsonwebtoken::jwk::Jwk) {
    let private_key_pem = "-----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A
        5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV
        b0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT
        -----END PRIVATE KEY-----
    "
    .to_string();

    let public_key: jsonwebtoken::jwk::Jwk = serde_json::from_str(
        r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
            "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
        }"#,
    )
    .unwrap();

    (private_key_pem, public_key)
}

fn create_test_bearer_token(tenant_id: Uuid) -> String {
    let (private_pem, public_key) = create_test_keypair();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({
        "sub": tenant_id,
        "iat": now,
        "exp": now + 3600,
    });

    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(public_key);

    encode(&header, &claims, &encoding_key).unwrap()
}

fn mock_session(session_id: &str, state: IssuanceState) -> IssuanceSession {
    let context = serde_json::from_value(serde_json::json!({
        "offer": {
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_id"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "pre-auth-code",
                    "tx_code": {
                        "input_mode": "numeric",
                        "length": 6,
                        "description": "Enter the one-time code."
                    }
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
            "response_types_supported": ["code"],
            "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        },
        "flow": {
            "PreAuthorizedCode": {
                "pre_authorized_code": "pre-auth-code",
                "tx_code": {
                    "input_mode": "numeric",
                    "length": 6,
                    "description": "Enter the one-time code."
                }
            }
        }
    }))
    .unwrap();

    let mut session = IssuanceSession::new(Uuid::new_v4(), context, FlowType::PreAuthorizedCode);
    session.id = session_id.to_owned();
    session.state = state;
    session.selected_config_ids = vec!["test_id".to_owned()];
    session
}

#[tokio::test]
async fn valid_tx_code_transitions_session_to_processing_and_enqueues_task() {
    let session_id = "ses_tx_code_success";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingTxCode);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_tx_code_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{session_id}/tx-code",
            app.base_url
        ))
        .bearer_auth(&app.auth_token)
        .json(&serde_json::json!({ "tx_code": "493821" }))
        .send()
        .await
        .expect("failed to send tx-code request");

    assert_eq!(response.status(), 202);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["session_id"], session_id);

    let session: IssuanceSession = app.session_store.get(session_id).await.unwrap().unwrap();
    assert_eq!(session.state, IssuanceState::Processing);

    let tasks = app.pushed_tasks.lock().unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].session_id, session_id);
    assert_eq!(
        tasks[0].pre_authorized_code.as_deref(),
        Some("pre-auth-code")
    );
    assert_eq!(tasks[0].tx_code.as_deref(), Some("493821"));
}

#[tokio::test]
async fn empty_tx_code_returns_400() {
    let session_id = "ses_tx_code_empty";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingTxCode);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_tx_code_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{session_id}/tx-code",
            app.base_url
        ))
        .bearer_auth(&app.auth_token)
        .json(&serde_json::json!({ "tx_code": "" }))
        .send()
        .await
        .expect("failed to send tx-code request");

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["error"], "invalid_tx_code");
    assert!(app.pushed_tasks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn non_numeric_tx_code_returns_400() {
    let session_id = "ses_tx_code_non_numeric";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::AwaitingTxCode);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_tx_code_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{session_id}/tx-code",
            app.base_url
        ))
        .bearer_auth(&app.auth_token)
        .json(&serde_json::json!({ "tx_code": "49A821" }))
        .send()
        .await
        .expect("failed to send tx-code request");

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["error"], "invalid_tx_code");
}

#[tokio::test]
async fn wrong_session_state_returns_409() {
    let session_id = "ses_tx_code_wrong_state";
    let session_store = MemorySession::new(Duration::from_secs(5));
    let mock_session = mock_session(session_id, IssuanceState::Processing);
    session_store
        .upsert(session_id, &mock_session)
        .await
        .unwrap();
    let app = spawn_tx_code_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{session_id}/tx-code",
            app.base_url
        ))
        .bearer_auth(&app.auth_token)
        .json(&serde_json::json!({ "tx_code": "493821" }))
        .send()
        .await
        .expect("failed to send tx-code request");

    assert_eq!(response.status(), 409);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["error"], "invalid_session_state");
}

#[tokio::test]
async fn unknown_session_returns_404() {
    let session_store = MemorySession::new(Duration::from_secs(5));
    let app = spawn_tx_code_test_app(session_store).await;
    let client = Client::new();

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/tx-code",
            app.base_url, "ses_tx_code_unknown"
        ))
        .bearer_auth(&app.auth_token)
        .json(&serde_json::json!({ "tx_code": "493821" }))
        .send()
        .await
        .expect("failed to send tx-code request");

    assert_eq!(response.status(), 404);
    let body: serde_json::Value = response.json().await.expect("failed to parse response");
    assert_eq!(body["error"], "session_not_found");
}
