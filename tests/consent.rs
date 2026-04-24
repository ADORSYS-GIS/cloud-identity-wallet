use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use cloud_identity_wallet::{
    domain::service::Service,
    issuance::AuthorizationUrlBuilder,
    outbound::{MemorySessionRepository, MemoryTenantRepository},
    server::{handlers::submit_consent, sse::SseEvent, AppState},
    session::{FlowType, IssuanceSession},
};
use cloud_wallet_openid4vc::http::HttpClientBuilder;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

fn create_test_state() -> AppState {
    let session_repo = MemorySessionRepository::new();
    let (sse_broadcast, _) = tokio::sync::broadcast::channel::<SseEvent>(16);

    let http_client = HttpClientBuilder::new()
        .allow_http_urls(true)
        .build()
        .unwrap();
    let authz_url_builder = AuthorizationUrlBuilder::new(
        "test-wallet".to_string(),
        url::Url::parse("http://localhost:3000/api/v1/issuance/callback").unwrap(),
        http_client,
    );

    let service = Service::new(
        MemoryTenantRepository::new(),
        session_repo,
        authz_url_builder,
        sse_broadcast,
    );

    AppState {
        service: Arc::new(service),
    }
}

fn create_test_session(flow: FlowType) -> IssuanceSession {
    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_credential_id"],
        "grants": {
            "authorization_code": {
                "issuer_state": "test_issuer_state"
            }
        }
    }))
    .unwrap();

    let authz_server_metadata = serde_json::from_value(json!({
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token"
    }))
    .unwrap();

    IssuanceSession::new(uuid::Uuid::new_v4(), offer, flow, authz_server_metadata).unwrap()
}

#[tokio::test]
async fn test_consent_rejected() {
    let state = create_test_state();
    let session = create_test_session(FlowType::AuthorizationCode);
    let session_id = session.id.clone();
    state.service.session_repo.save(&session).await.unwrap();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": false}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
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
    state.service.session_repo.save(&session).await.unwrap();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 409 CONFLICT for invalid session state
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["error"], "invalid_session_state");
}

#[tokio::test]
async fn test_consent_session_not_found() {
    let state = create_test_state();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/issuance/nonexistent/consent")
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["error"], "session_not_found");
}

#[tokio::test]
async fn test_consent_authorization_code_flow() {
    let state = create_test_state();
    let session = create_test_session(FlowType::AuthorizationCode);
    let session_id = session.id.clone();
    
    // Clone session_repo for later verification before moving state
    let session_repo = state.service.session_repo.clone();
    session_repo.save(&session).await.unwrap();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true, "selected_configuration_ids": ["test_credential_id"]}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    // Verify next_action is "redirect"
    assert_eq!(result["next_action"], "redirect");
    
    // Verify authorization_url is present and contains expected parameters
    let authz_url = result["authorization_url"].as_str().expect("authorization_url should be present");
    assert!(authz_url.contains("response_type=code"), "should contain response_type=code");
    assert!(authz_url.contains("client_id=test-wallet"), "should contain client_id");
    assert!(authz_url.contains(&format!("state={}", session_id)), "should contain state=session_id");
    assert!(authz_url.contains("code_challenge="), "should contain code_challenge");
    assert!(authz_url.contains("code_challenge_method=S256"), "should contain code_challenge_method=S256");
    assert!(authz_url.contains("issuer_state=test_issuer_state"), "should contain issuer_state from offer");
    
    // Verify code_verifier is NOT in the response (security requirement)
    assert!(!authz_url.contains("code_verifier"), "code_verifier must never be in response");
    
    // Verify session was updated with code_verifier stored internally
    let updated_session = session_repo.get(&session_id).await.unwrap().unwrap();
    assert!(updated_session.code_verifier.is_some(), "code_verifier should be stored in session");
    assert_eq!(updated_session.state, cloud_identity_wallet::session::IssuanceState::AwaitingAuthorization);
}

#[tokio::test]
async fn test_consent_pre_authorized_no_tx_code() {
    let state = create_test_state();

    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_credential_id"],
        "grants": {
            "pre-authorized_code": {
                "pre-authorized_code": "test_code"
            }
        }
    }))
    .unwrap();

    let authz_server_metadata = serde_json::from_value(json!({
        "issuer": "https://as.example.com",
        "token_endpoint": "https://as.example.com/token"
    }))
    .unwrap();

    let session = IssuanceSession::new(uuid::Uuid::new_v4(), offer, FlowType::PreAuthorizedCode, authz_server_metadata).unwrap();
    let session_id = session.id.clone();
    state.service.session_repo.save(&session).await.unwrap();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["next_action"], "none");
}

#[tokio::test]
async fn test_consent_pre_authorized_with_tx_code() {
    let state = create_test_state();

    let offer = serde_json::from_value(json!({
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["test_credential_id"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "test_code",
                "tx_code": {
                    "input_mode": "numeric",
                    "length": 6
                }
            }
        }
    }))
    .unwrap();

    let authz_server_metadata = serde_json::from_value(json!({
        "issuer": "https://as.example.com",
        "token_endpoint": "https://as.example.com/token"
    }))
    .unwrap();

    let session = IssuanceSession::new(uuid::Uuid::new_v4(), offer, FlowType::PreAuthorizedCode, authz_server_metadata).unwrap();
    let session_id = session.id.clone();
    state.service.session_repo.save(&session).await.unwrap();

    let app = axum::Router::new()
        .route("/api/v1/issuance/{session_id}/consent", axum::routing::post(submit_consent))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/v1/issuance/{}/consent", session_id))
                .header("content-type", "application/json")
                .body(Body::from(json!({"accepted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["next_action"], "provide_tx_code");
}
