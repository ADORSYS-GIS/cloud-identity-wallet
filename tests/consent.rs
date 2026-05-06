use cloud_identity_wallet::{
    domain::models::
        issuance::FlowType
    ,
    session::{IssuanceSession, IssuanceState, MemorySession, SessionStore},
};
use cloud_wallet_openid4vc::issuance::client::ResolvedOfferContext;
use serde_json::json;
use std::time::Duration;

fn create_test_session(flow: FlowType) -> IssuanceSession {
    use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;
    use cloud_wallet_openid4vc::issuance::client::IssuanceFlow;
    use cloud_wallet_openid4vc::issuance::credential_offer::CredentialOffer;
    use cloud_wallet_openid4vc::issuance::issuer_metadata::CredentialIssuerMetadata;

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

/// Helper to create a session store with a session in AwaitingConsent state
async fn setup_session(flow: FlowType) -> (MemorySession, String, IssuanceSession) {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(flow);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();
    (session_store, session_id.to_string(), session)
}

/// Test that a session in AwaitingConsent state can be retrieved
#[tokio::test]
async fn test_session_awaiting_consent_retrieval() {
    let (session_store, session_id, _session) = setup_session(FlowType::AuthorizationCode).await;

    // Verify session exists and is in correct state
    let retrieved: Option<IssuanceSession> = session_store.get(session_id.as_str()).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.state, IssuanceState::AwaitingConsent);
    assert_eq!(retrieved.flow, FlowType::AuthorizationCode);
}

/// Test that a non-existent session returns None
#[tokio::test]
async fn test_session_not_found() {
    let session_store = MemorySession::new(Duration::from_secs(900));

    let retrieved: Option<IssuanceSession> = session_store.get("nonexistent").await.unwrap();
    assert!(retrieved.is_none());
}

/// Test that a session in wrong state (not AwaitingConsent) can be detected
#[tokio::test]
async fn test_session_invalid_state_detection() {
    let (session_store, session_id, mut session) = setup_session(FlowType::AuthorizationCode).await;

    // Change session state to Processing (not AwaitingConsent)
    session.state = IssuanceState::Processing;
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    // Verify session is in wrong state
    let retrieved: Option<IssuanceSession> = session_store.get(session_id.as_str()).await.unwrap();
    let retrieved = retrieved.unwrap();
    assert_ne!(retrieved.state, IssuanceState::AwaitingConsent);
    assert_eq!(retrieved.state, IssuanceState::Processing);
}

/// Test session removal (for rejected consent)
#[tokio::test]
async fn test_session_removal() {
    let (session_store, session_id, _) = setup_session(FlowType::AuthorizationCode).await;

    // Remove the session
    session_store.remove(session_id.as_str()).await.unwrap();

    // Verify session no longer exists
    let exists = session_store.exists(session_id.as_str()).await.unwrap();
    assert!(!exists);
}

/// Test session state transition
#[tokio::test]
async fn test_session_state_transition() {
    let (session_store, session_id, mut session) = setup_session(FlowType::AuthorizationCode).await;

    // Transition to AwaitingAuthorization state
    session.state = IssuanceState::AwaitingAuthorization;
    session.code_verifier = Some("test_verifier".to_string());
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    // Verify state transition
    let retrieved: Option<IssuanceSession> = session_store.get(session_id.as_str()).await.unwrap();
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.state, IssuanceState::AwaitingAuthorization);
    assert_eq!(retrieved.code_verifier, Some("test_verifier".to_string()));
}

/// Test pre-authorized code flow session
#[tokio::test]
async fn test_pre_authorized_code_session() {
    let (session_store, session_id, _session) = setup_session(FlowType::PreAuthorizedCode).await;

    // Verify session is in correct state for pre-authorized code
    let retrieved: Option<IssuanceSession> = session_store.get(session_id.as_str()).await.unwrap();
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.state, IssuanceState::AwaitingConsent);
    assert_eq!(retrieved.flow, FlowType::PreAuthorizedCode);
}

/// Test that session expiration works
#[tokio::test]
async fn test_session_expiration() {
    // Create session with very short TTL
    let session_store = MemorySession::new(Duration::from_millis(1));
    let session = create_test_session(FlowType::AuthorizationCode);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Session should be expired and return None
    let retrieved: Option<IssuanceSession> = session_store.get(session_id.as_str()).await.unwrap();
    assert!(retrieved.is_none());
}

/// Test consent request parsing
#[tokio::test]
async fn test_consent_request_rejected() {
    use cloud_identity_wallet::domain::models::issuance::ConsentRequest;

    let request = serde_json::from_value::<ConsentRequest>(json!({
        "accepted": false
    }))
    .unwrap();

    assert!(!request.accepted);
    assert!(request.selected_configuration_ids.is_empty());
}

/// Test consent request with selected configurations
#[tokio::test]
async fn test_consent_request_with_configurations() {
    use cloud_identity_wallet::domain::models::issuance::ConsentRequest;

    let request = serde_json::from_value::<ConsentRequest>(json!({
        "accepted": true,
        "selected_configuration_ids": ["cred1", "cred2"]
    }))
    .unwrap();

    assert!(request.accepted);
    assert_eq!(request.selected_configuration_ids, vec!["cred1", "cred2"]);
}

/// Test consent response serialization
#[tokio::test]
async fn test_consent_response_serialization() {
    use cloud_identity_wallet::domain::models::issuance::{ConsentResponse, NextAction};

    let response = ConsentResponse {
        session_id: "test-session".to_string(),
        next_action: NextAction::Rejected,
        authorization_url: None,
    };

    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["session_id"], "test-session");
    assert_eq!(json["next_action"], "rejected");
    assert!(!json.as_object().unwrap().contains_key("authorization_url"));
}

/// Test consent response with redirect
#[tokio::test]
async fn test_consent_response_with_redirect() {
    use cloud_identity_wallet::domain::models::issuance::{ConsentResponse, NextAction};

    let response = ConsentResponse {
        session_id: "test-session".to_string(),
        next_action: NextAction::Redirect,
        authorization_url: Some("https://example.com/authorize".to_string()),
    };

    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["session_id"], "test-session");
    assert_eq!(json["next_action"], "redirect");
    assert_eq!(json["authorization_url"], "https://example.com/authorize");
}
