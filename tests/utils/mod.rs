#![allow(dead_code)]

use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::{
            credential::{Credential, CredentialFormat, CredentialStatus},
            issuance::IssuanceEngine,
        },
        service::Service,
    },
    outbound::{
        MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
        MemoryTenantRepo,
    },
    server::Server,
    session::MemorySession,
};
use cloud_wallet_crypto::ecdsa::{Curve, KeyPair as EcdsaKeyPair};
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sqlx::{AnyPool, ConnectOptions};
use time::{OffsetDateTime, UtcDateTime};
use url::Url;
use uuid::Uuid;

/// Create a signed Bearer token whose `sub` claim is `tenant_id`.
///
/// Uses a freshly generated P-256 keypair so the live server can verify
/// the token without any additional setup.
pub fn create_bearer_token(tenant_id: &Uuid) -> String {
    create_test_bearer_token(*tenant_id)
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
    let credential_repo = MemoryCredentialRepo::new();
    let client_config = Oid4vciClientConfig::new(
        config.oid4vci.client_id.clone(),
        config.oid4vci.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vci.use_system_proxy)
    .accept_untrusted_hosts(true);
    let client = Oid4vciClient::new(client_config).unwrap();
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    let engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        subscriber,
        credential_repo.clone(),
        tenant_repo.clone(),
        &session_store,
    );
    let service = Service::new(session_store, tenant_repo, engine);
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
