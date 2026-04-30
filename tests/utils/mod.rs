#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::credential::{Credential, CredentialFormat, CredentialStatus},
        service::Service,
    },
    outbound::{SqlTenantRepo, TenantKeyAlg},
    server::Server,
    session::MemorySession,
};
use cloud_wallet_crypto::ecdsa::Curve;
use cloud_wallet_kms::provider::LocalProvider;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::Jwk};
use serde::{Deserialize, Serialize};
use sqlx::{AnyPool, ConnectOptions};
use std::fs;
use time::{OffsetDateTime, UtcDateTime};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Claims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

pub fn create_test_keypair() -> (String, Jwk) {
    let private_key_pem = fs::read_to_string("tests/test_data/test_private_key.pem")
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

    let local_kms_provider = LocalProvider::new();
    let alg = TenantKeyAlg::Ecdsa(Curve::P256);

    let tenant_repo: SqlTenantRepo = SqlTenantRepo::new(pool, alg, local_kms_provider);
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

pub fn sample_credential(tenant_id: Uuid) -> Credential {
    Credential {
        id: Uuid::new_v4(),
        tenant_id,
        issuer: "https://issuer.example".to_string(),
        subject: Some("did:example:alice".to_string()),
        credential_types: vec![
            "VerifiableCredential".to_string(),
            "EmployeeBadge".to_string(),
        ],
        format: CredentialFormat::JwtVcJson,
        external_id: Some("https://issuer.example/ext-123".to_string()),
        status: CredentialStatus::Active,
        issued_at: UtcDateTime::now(),
        valid_until: None,
        is_revoked: false,
        status_location: Some(Url::parse("https://status.example/42").unwrap()),
        status_index: Some(42),
        raw_credential: "eyJhbGciOiJFZERTQSJ9.payload.signature".to_string(),
    }
}

pub async fn insert_tenant(pool: &AnyPool, id: Uuid, name: &str) {
    let url = pool.connect_options().to_url_lossy();
    let is_postgres =
        url.as_str().starts_with("postgres://") || url.as_str().starts_with("postgresql://");
    let key_algorithm = "eddsa";
    let key_material = vec![0u8; 32];
    let created_at = UtcDateTime::now().unix_timestamp();

    let query = if is_postgres {
        "INSERT INTO tenants (id, name, key_algorithm, key_material, created_at) VALUES ($1, $2, $3, $4, $5)"
    } else {
        "INSERT INTO tenants (id, name, key_algorithm, key_material, created_at) VALUES (?, ?, ?, ?, ?)"
    };

    sqlx::query(query)
        .bind(id.to_string())
        .bind(name)
        .bind(key_algorithm)
        .bind(key_material)
        .bind(created_at)
        .execute(pool)
        .await
        .unwrap();
}
