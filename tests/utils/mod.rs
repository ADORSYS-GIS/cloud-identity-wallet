#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config, domain::service::Service, outbound::SqlTenantRepository, server::Server,
    session::MemorySession,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::Jwk};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Claims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub fn create_test_keypair() -> (String, Jwk) {
    let private_key_pem = std::fs::read_to_string("tests/test_data/test_private_key.pem")
        .expect("Failed to read test_private_key.pem");

    let public_key: Jwk = serde_json::from_str(
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

pub fn create_test_token(sub: &Uuid, encoding_key: &EncodingKey, jwk: Option<Jwk>) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let claims = Claims {
        sub: *sub,
        iat: now,
        exp: now + 3600,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.jwk = jwk;

    encode(&header, &claims, encoding_key).unwrap()
}

pub async fn spawn_server() -> String {
    // Install default drivers for sqlx
    sqlx::any::install_default_drivers();

    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    // Create in-memory database for testing
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let tenant_repo = SqlTenantRepository::new(pool);
    tenant_repo.init_schema().await.unwrap();
    let session_store = MemorySession::default();

    let service = Service::new(session_store, tenant_repo);
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}

pub async fn create_authenticated_client_and_token() -> (reqwest::Client, String, Uuid) {
    let client = reqwest::Client::new();
    let (private_pem, public_key) = create_test_keypair();
    let tenant_id = Uuid::new_v4();
    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes()).unwrap();
    let token = create_test_token(&tenant_id, &encoding_key, Some(public_key));
    let auth_header = format!("Bearer {}", token);

    (client, auth_header, tenant_id)
}
