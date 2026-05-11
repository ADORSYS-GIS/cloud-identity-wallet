use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::credential::{Credential, CredentialFormat, CredentialStatus},
        ports::CredentialRepo,
    },
    outbound::MemoryTenantRepo,
    server::Server,
    session::MemorySession,
    setup,
};
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sqlx::{AnyPool, ConnectOptions};
use time::{OffsetDateTime, UtcDateTime};
use url::Url;

/// Aborts the server task when dropped, preventing socket/fd leaks between tests.
#[allow(dead_code)]
pub struct ServerHandle(tokio::task::JoinHandle<color_eyre::eyre::Result<()>>);

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn make_config() -> Config {
    let mut config = Config::load().unwrap();
    config.server.host = "localhost".to_string();
    config.server.port = 0;
    config.oid4vci.use_system_proxy = false;
    config
}

/// Spawns a test server and returns its base URL.
///
/// The server task runs until the test process exits (fire-and-forget). Use
/// [`spawn_server_with_repo`] when you need direct repo access or controlled
/// server teardown.
pub async fn spawn_server() -> String {
    let config = make_config();
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();
    let service = setup::build_service(session_store, tenant_repo, &config).unwrap();
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();
    tokio::spawn(server.run());
    format!("http://{}:{}", config.server.host, port)
}

/// Spawns a test server and returns the base URL, the shared credential
/// repository for direct seeding, and a [`ServerHandle`] that aborts the
/// server task when dropped.
///
/// Keep the `ServerHandle` alive for the duration of the test.
#[allow(dead_code)]
pub async fn spawn_server_with_repo() -> (String, Arc<dyn CredentialRepo>, ServerHandle) {
    let config = make_config();
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();
    let service = setup::build_service(session_store, tenant_repo, &config).unwrap();
    let credential_repo = Arc::clone(&service.issuance_engine.credential_repo);
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();
    let handle = ServerHandle(tokio::spawn(server.run()));
    (
        format!("http://{}:{}", config.server.host, port),
        credential_repo,
        handle,
    )
}

/// Generates a fresh P-256 key pair at runtime.
///
/// Returns an [`EncodingKey`] for signing JWTs and the matching public JWK
/// value for embedding in the JWT header (so the auth middleware can verify).
#[allow(dead_code)]
pub fn create_test_keypair() -> (EncodingKey, serde_json::Value) {
    let key_pair = KeyPair::generate(Curve::P256).expect("P-256 key generation should not fail");

    // jsonwebtoken requires EC private keys as PEM; convert PKCS8 DER → PEM
    let b64 = STANDARD.encode(key_pair.to_pkcs8_der());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is always valid ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())
        .expect("PEM-encoded EC private key should be valid");

    // Extract uncompressed EC point: 0x04 || x(32 bytes) || y(32 bytes)
    let mut point = [0u8; 65];
    key_pair
        .public_key()
        .to_sec1_uncompressed(&mut point)
        .expect("Uncompressed point extraction should not fail");

    let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&point[33..65]);

    let jwk = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });

    (encoding_key, jwk)
}

/// Mints a test JWT for the given tenant, signed with `encoding_key` and
/// carrying `jwk` in the header for self-contained verification.
#[allow(dead_code)]
pub fn create_token(tenant_id: Uuid, encoding_key: &EncodingKey, jwk: serde_json::Value) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = json!({ "sub": tenant_id, "iat": now, "exp": now + 3600 });
    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(serde_json::from_value(jwk).expect("JWK value must be valid"));
    encode(&header, &claims, encoding_key).expect("JWT signing should not fail")
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub async fn insert_tenant(pool: &AnyPool, id: Uuid, name: &str) {
    let url = pool.connect_options().to_url_lossy();
    let is_postgres =
        url.as_str().starts_with("postgres://") || url.as_str().starts_with("postgresql://");
    let key_algorithm = "eddsa";
    let key_material = vec![0u8; 32];
    let created_at = OffsetDateTime::now_utc().unix_timestamp();

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

/// Creates a fresh P-256 keypair for testing purposes.
/// Returns (EncodingKey, public JWK as serde_json::Value).
///
/// This function generates a new random keypair each time it is called,
/// ensuring tests exercise real key generation logic.
pub fn create_test_keypair() -> (EncodingKey, serde_json::Value) {
    use cloud_wallet_crypto::jwk::Jwk;

    let keypair = EcdsaKeyPair::generate(Curve::P256).expect("failed to generate P-256 keypair");
    let der = keypair.to_pkcs8_der();
    let encoding_key = EncodingKey::from_ec_der(der);

    // Convert to JWK using the cloud_wallet_crypto library
    let jwk: Jwk = Jwk::try_from(&keypair).expect("failed to convert to JWK");
    let public_jwk = serde_json::to_value(jwk).expect("failed to serialize JWK");

    (encoding_key, public_jwk)
}

/// Creates a test JWT bearer token for authentication in integration tests.
///
/// This function generates a new keypair and creates a signed JWT token
/// with the given tenant_id as the subject claim. The token is valid for 1 hour.
///
/// # Arguments
/// * `tenant_id` - The UUID to use as the subject claim in the token
///
/// # Returns
/// A signed JWT token string suitable for use in Authorization headers
pub fn create_test_bearer_token(tenant_id: Uuid) -> String {
    let (encoding_key, public_jwk) = create_test_keypair();
    let public_key: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(public_jwk).expect("failed to parse public JWK");

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({
        "sub": tenant_id,
        "iat": now,
        "exp": now + 3600,
    });

    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(public_key);

    encode(&header, &claims, &encoding_key).expect("failed to encode JWT")
}
