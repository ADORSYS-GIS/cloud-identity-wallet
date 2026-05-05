use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use cloud_wallet_openid4vc::issuance::client::{
    Config as Oid4vciClientConfig, IssuanceFlow, Oid4vciClient, ResolvedOfferContext,
};
use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;
use cloud_wallet_openid4vc::issuance::credential_offer::{
    CredentialOffer, Grants, InputMode, PreAuthorizedCodeGrant, TxCode as Oid4vciTxCode,
};
use cloud_wallet_openid4vc::issuance::issuer_metadata::CredentialIssuerMetadata;
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use url::Url;

use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::models::issuance::FlowType;
use crate::outbound::{MemoryCredentialRepo, MemoryEventPublisher, MemoryTaskQueue, MemoryTenantRepo};
use crate::server::AppState;
use crate::server::handlers::issuance::{
    ErrorResponse, TxCodeResponse, cancel_session, submit_tx_code,
};
use crate::server::sse::SseBroadcaster;
use crate::session::{IssuanceSession, IssuanceState, MemorySession, SessionStore};

async fn create_test_state() -> (AppState<MemorySession>, String) {
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();
    let broadcaster = SseBroadcaster::new();

    let offer = CredentialOffer {
        credential_issuer: Url::parse("https://issuer.example.com").unwrap(),
        credential_configuration_ids: vec!["test_id".to_string()],
        grants: Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: "abc123".to_string(),
                tx_code: Some(Oid4vciTxCode {
                    input_mode: Some(InputMode::Numeric),
                    length: Some(6),
                    description: Some("Enter the 6-digit code sent to your phone".to_string()),
                }),
                authorization_server: None,
            }),
        }),
    };

    let issuer_metadata: CredentialIssuerMetadata = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "credential_configurations_supported": {
            "test_id": {
                "format": "dc+sd-jwt",
                "vct": "https://credentials.example.com/test"
            }
        }
    }))
    .unwrap();

    let as_metadata: AuthorizationServerMetadata = serde_json::from_value(json!({
        "issuer": "https://issuer.example.com",
        "authorization_endpoint": "https://issuer.example.com/authorize",
        "token_endpoint": "https://issuer.example.com/token",
        "response_types_supported": ["code"]
    }))
    .unwrap();

    let flow = IssuanceFlow::PreAuthorizedCode {
        pre_authorized_code: "abc123".to_string(),
        tx_code: Some(Oid4vciTxCode {
            input_mode: Some(InputMode::Numeric),
            length: Some(6),
            description: Some("Enter the 6-digit code sent to your phone".to_string()),
        }),
    };

    let context = ResolvedOfferContext {
        offer,
        issuer_metadata,
        as_metadata,
        flow,
    };

    let session = IssuanceSession::new(
        uuid::Uuid::new_v4(),
        context,
        FlowType::PreAuthorizedCode,
    )
    .unwrap();

    let session_id = session.id.clone();
    let mut session = session;
    session.state = IssuanceState::AwaitingTxCode;
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let client_config = Oid4vciClientConfig::new(
        "test-client",
        Url::parse("https://wallet.example.com/callback").unwrap(),
    );
    let client = Oid4vciClient::new(client_config).unwrap();
    let task_queue = MemoryTaskQueue::new();
    let event_publisher = MemoryEventPublisher::new(16);
    let credential_repo = MemoryCredentialRepo::new();

    let issuance_engine = IssuanceEngine::new(
        client,
        task_queue,
        event_publisher,
        credential_repo,
        tenant_repo.clone(),
        &session_store,
    );

    let state = AppState {
        issuance_store: Arc::new(session_store.clone()),
        tenant_repo: Arc::new(tenant_repo),
        broadcaster,
        issuance_engine,
    };

    (state, session_id)
}

#[tokio::test]
async fn test_submit_tx_code_valid_numeric_code() {
    let (state, session_id) = create_test_state().await;

    let app = Router::new()
        .route(
            "/api/v1/issuance/{session_id}/tx-code",
            post(submit_tx_code),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/tx-code", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"tx_code": "123456"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: TxCodeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.session_id, session_id);
}

#[tokio::test]
async fn test_submit_tx_code_invalid_non_numeric() {
    let (state, session_id) = create_test_state().await;

    let app = Router::new()
        .route(
            "/api/v1/issuance/{session_id}/tx-code",
            post(submit_tx_code),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/tx-code", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"tx_code": "abcdef"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.error, "invalid_tx_code");
}

#[tokio::test]
async fn test_submit_tx_code_invalid_length() {
    let (state, session_id) = create_test_state().await;

    let app = Router::new()
        .route(
            "/api/v1/issuance/{session_id}/tx-code",
            post(submit_tx_code),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/tx-code", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"tx_code": "12345"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.error, "invalid_tx_code");
}

#[tokio::test]
async fn test_submit_tx_code_session_not_found() {
    let (state, _) = create_test_state().await;

    let app = Router::new()
        .route(
            "/api/v1/issuance/{session_id}/tx-code",
            post(submit_tx_code),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/issuance/nonexistent-session/tx-code")
                .header("content-type", "application/json")
                .body(Body::from(json!({"tx_code": "123456"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_submit_tx_code_invalid_session_state() {
    let (state, session_id) = create_test_state().await;

    let mut session: IssuanceSession = state
        .issuance_store
        .get(session_id.as_str())
        .await
        .unwrap()
        .unwrap();
    session.state = IssuanceState::Processing;
    state
        .issuance_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let app = Router::new()
        .route(
            "/api/v1/issuance/{session_id}/tx-code",
            post(submit_tx_code),
        )
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/tx-code", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"tx_code": "123456"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_cancel_session_success() {
    let (state, session_id) = create_test_state().await;

    let app = Router::new()
        .route("/api/v1/issuance/{session_id}/cancel", post(cancel_session))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/cancel", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_cancel_session_not_found() {
    let (state, _) = create_test_state().await;

    let app = Router::new()
        .route("/api/v1/issuance/{session_id}/cancel", post(cancel_session))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/issuance/nonexistent-session/cancel")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_cancel_session_already_completed() {
    let (state, session_id) = create_test_state().await;

    let mut session: IssuanceSession = state
        .issuance_store
        .get(session_id.as_str())
        .await
        .unwrap()
        .unwrap();
    session.state = IssuanceState::Completed;
    state
        .issuance_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let app = Router::new()
        .route("/api/v1/issuance/{session_id}/cancel", post(cancel_session))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/cancel", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.error, "invalid_session_state");
}

#[tokio::test]
async fn test_cancel_session_already_failed() {
    let (state, session_id) = create_test_state().await;

    let mut session: IssuanceSession = state
        .issuance_store
        .get(session_id.as_str())
        .await
        .unwrap()
        .unwrap();
    session.state = IssuanceState::Failed;
    state
        .issuance_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let app = Router::new()
        .route("/api/v1/issuance/{session_id}/cancel", post(cancel_session))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/issuance/{}/cancel", session_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}
