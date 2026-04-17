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

use crate::domain::models::{Session, SessionState, TxCodeSpec};
use crate::domain::{InMemorySessionStore, SessionStore};
use crate::server::handlers::issuance::{
    ErrorResponse, IssuanceState, TxCodeResponse, cancel_session, submit_tx_code,
};
use crate::server::sse::SseBroadcaster;
use cloud_wallet_openid4vc::issuance::credential_offer::InputMode;

async fn create_test_state() -> (Arc<IssuanceState>, String) {
    let session_store = Arc::new(InMemorySessionStore::new());
    let broadcaster = SseBroadcaster::new();

    let tx_code_spec = Some(TxCodeSpec {
        input_mode: InputMode::Numeric,
        length: Some(6),
        description: Some("Enter the 6-digit code sent to your phone".to_string()),
    });

    let session_id = "test-session-123".to_string();
    let mut session = Session::new(session_id.clone(), uuid::Uuid::nil(), tx_code_spec);
    session.state = SessionState::AwaitingTxCode;
    session_store.insert(session).await.unwrap();

    let state = Arc::new(IssuanceState {
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
        .update_state(&session_id, SessionState::Processing)
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
        .update_state(&session_id, SessionState::Completed)
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
        .update_state(&session_id, SessionState::Failed)
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
