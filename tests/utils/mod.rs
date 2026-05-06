#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config,
    domain::models::credential::{Credential, CredentialFormat, CredentialStatus},
    outbound::{MemoryCredentialRepo, MemoryTenantRepo},
    server::Server,
    session::MemorySession,
    setup,
};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sqlx::{AnyPool, ConnectOptions};
use time::{OffsetDateTime, UtcDateTime};
use url::Url;
use uuid::Uuid;

/// Claims used when constructing test JWTs.
#[derive(serde::Serialize)]
struct TestClaims {
    sub: Uuid,
    iat: i64,
    exp: i64,
}

/// Create a signed Bearer token whose `sub` claim is `tenant_id`.
///
/// Uses the same P-256 test key pair embedded in the auth middleware tests so
/// the live server can verify the token without any additional setup.
pub fn create_bearer_token(tenant_id: &Uuid) -> String {
    let private_key_pem = "-----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsJyilHyjhzXDVU2A
        5ud6kfXPktY7wx5d8CQFe1nMzK2hRANCAAQ17IW//Yvrs4SmU1smlHTYgWKzj+UV
        b0diaF8Xk6vqb3gB9qnvD4NxkNvLsQPPqjQKncEP831drigLydrC6WPT
        -----END PRIVATE KEY-----
    ";

    let public_key: Jwk = serde_json::from_str(
        r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "NeyFv_2L67OEplNbJpR02IFis4_lFW9HYmhfF5Or6m8",
            "y": "eAH2qe8Pg3GQ28uxA8-qNAqdwQ_zfV2uKAvJ2sLpY9M"
        }"#,
    )
    .unwrap();

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = TestClaims {
        sub: *tenant_id,
        iat: now,
        exp: now + 3600,
    };

    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .expect("test private key must be valid");

    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(public_key);

    encode(&header, &claims, &encoding_key).expect("test JWT encoding must succeed")
}

/// Internal helper to spawn a server and return `(base_url, credential_repo)`.
async fn spawn_server_internal() -> (String, MemoryCredentialRepo) {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config.oid4vci.use_system_proxy = false;
        config
    };
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();
    let (service, credential_repo) =
        setup::build_service_with_repo(session_store, tenant_repo, &config).unwrap();
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    (
        format!("http://{}:{}", config.server.host, port),
        credential_repo,
    )
}

/// Spawn a test server and return its base URL.
pub async fn spawn_server() -> String {
    spawn_server_internal().await.0
}

/// Spawn a test server and return `(base_url, credential_repo)`.
///
/// The returned `MemoryCredentialRepo` shares storage with the running server,
/// allowing tests to pre-populate credentials via `upsert` before making HTTP
/// requests.
pub async fn spawn_server_with_repo() -> (String, MemoryCredentialRepo) {
    spawn_server_internal().await
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
