use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

use crate::domain::{InMemorySessionStore, SessionStore};
use crate::server::AppState;
use crate::server::handlers::issuance::{
    ErrorResponse, TxCodeResponse, cancel_session, submit_tx_code,
};
use crate::server::sse::SseBroadcaster;
use crate::session::{FlowType, IssuanceSession, IssuanceState};

async fn create_test_state() -> (Arc<AppState>, String) {
    let session_store = Arc::new(InMemorySessionStore::new());
    let broadcaster = SseBroadcaster::new();

    let offer = serde_json::from_value(serde_json::json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_id"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "abc123",
                "tx_code": {
                    "input_mode": "numeric",
                    "length": 6,
                    "description": "Enter the 6-digit code sent to your phone"
                }
            }
        }
    }))
    .unwrap();

    let mut session =
        IssuanceSession::new(uuid::Uuid::nil(), offer, FlowType::PreAuthorizedCode).unwrap();
    session.state = IssuanceState::AwaitingTxCode;
    let session_id = session.id.clone();
    session_store.insert(session).await.unwrap();

    let state = Arc::new(AppState {
        session_store,
        broadcaster,
    });

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

    state
        .session_store
        .update_state(&session_id, IssuanceState::Processing)
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

    state
        .session_store
        .update_state(&session_id, IssuanceState::Completed)
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

    state
        .session_store
        .update_state(&session_id, IssuanceState::Failed)
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
