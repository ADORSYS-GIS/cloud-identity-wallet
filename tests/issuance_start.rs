//! Integration tests for POST /api/v1/issuance/start

pub mod utils;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, StatusCode};
use serde_json::json;
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

#[tokio::test]
async fn missing_authorization_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_authorization_header_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", "InvalidToken")
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_bearer_token_returns_401() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", "Bearer invalid_jwt_token")
        .json(&json!({ "offer": "test" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_offer_with_valid_auth_returns_400() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "offer": "" }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body.get("error").unwrap(), "invalid_credential_offer");
}

#[tokio::test]
async fn missing_offer_field_returns_422() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({}))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn invalid_offer_uri_returns_bad_gateway() {
    let base_url = utils::spawn_server().await;
    let client = Client::new();

    let (private_pem, public_jwk) = create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(tenant_id, &encoding_key, public_jwk);

    let response = client
        .post(format!("{}/api/v1/issuance/start", base_url))
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "offer": "openid-credential-offer://?credential_offer_uri=https://nonexistent.invalid/offer.json"
        }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
