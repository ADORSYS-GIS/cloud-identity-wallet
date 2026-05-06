//! Integration tests for POST /api/v1/issuance/{session_id}/cancel

pub mod utils;

use cloud_identity_wallet::{
    domain::models::issuance::FlowType,
    session::{IssuanceSession, IssuanceState, MemorySession, SessionStore},
};
use cloud_wallet_openid4vc::issuance::client::ResolvedOfferContext;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

fn create_test_keypair() -> (String, serde_json::Value) {
    let private_key_pem = "-----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A
        5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV
        b0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT
        -----END PRIVATE KEY-----
    "
    .to_string();

    let public_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
        "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
    });

    (private_key_pem, public_jwk)
}

fn create_test_token(
    tenant_id: Uuid,
    encoding_key: &EncodingKey,
    jwk: serde_json::Value,
) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let claims = json!({
        "sub": tenant_id,
        "iat": now,
        "exp": now + 3600
    });

    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(serde_json::from_value(jwk).unwrap());

    encode(&header, &claims, encoding_key).unwrap()
}

fn create_test_session(flow: FlowType, state: IssuanceState) -> IssuanceSession {
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

    let mut session = IssuanceSession::new(uuid::Uuid::new_v4(), context, flow);
    session.state = state;
    session
}

#[tokio::test]
async fn cancel_non_existent_session_returns_404() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/nonexistent/cancel", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "session_not_found");
}

#[tokio::test]
async fn cancel_without_auth_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/test-session/cancel", base_url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cancel_active_session_returns_204() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(FlowType::AuthorizationCode, IssuanceState::AwaitingConsent);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cancel_completed_session_returns_409() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(FlowType::AuthorizationCode, IssuanceState::Completed);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "session_already_completed");
}

#[tokio::test]
async fn cancel_failed_session_returns_409() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(FlowType::AuthorizationCode, IssuanceState::Failed);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "session_already_completed");
}

#[tokio::test]
async fn cancel_processing_session_returns_204() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(FlowType::PreAuthorizedCode, IssuanceState::Processing);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cancel_awaiting_authorization_session_returns_204() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(
        FlowType::AuthorizationCode,
        IssuanceState::AwaitingAuthorization,
    );
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn cancel_awaiting_tx_code_session_returns_204() {
    let session_store = MemorySession::new(Duration::from_secs(900));
    let session = create_test_session(FlowType::PreAuthorizedCode, IssuanceState::AwaitingTxCode);
    let session_id = session.id.clone();
    session_store
        .upsert(session_id.as_str(), &session)
        .await
        .unwrap();

    let base_url = utils::spawn_server_with_session_store(session_store).await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = session.tenant_id;
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!(
            "{}/api/v1/issuance/{}/cancel",
            base_url, session_id
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
