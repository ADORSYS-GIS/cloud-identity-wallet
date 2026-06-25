#![allow(dead_code)]

use cloud_wallet_crypto::ecdsa::{Curve, KeyPair};
use cloud_wallet_crypto::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use time::OffsetDateTime;
use uuid::Uuid;

use cloud_identity_wallet::{
    config::Config,
    domain::{
        models::{
            credential::{Credential, CredentialFormat, CredentialStatus},
            issuance::IssuanceEngine,
        },
        ports::CredentialRepo,
        service::Service,
    },
    outbound::{
        MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
        MemoryTenantRepo,
    },
    server::Server,
    session::MemorySession,
    setup,
};
use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;
use sqlx::{AnyPool, ConnectOptions};
use time::UtcDateTime;
use url::Url;

/// Test server which holds the base URL and other necessary components for testing
pub struct TestServer<R>
where
    R: CredentialRepo,
{
    pub base_url: String,
    pub credential_repo: R,
}

/// Spawn a server and return the base URL and other necessary components
pub async fn spawn_server() -> TestServer<MemoryCredentialRepo> {
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
    let client = Oid4vciClient::new(OidClient::new(client_config).unwrap());
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    let issuance_engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        subscriber,
        credential_repo.clone(),
        tenant_repo.clone(),
        &session_store,
        config.oid4vci.preferred_display_locales.clone(),
    );
    let presentation_engine =
        setup::build_presentation_engine(&config, credential_repo.clone(), tenant_repo.clone())
            .expect("failed to build presentation engine");
    let service = Service::new(
        session_store,
        tenant_repo,
        issuance_engine,
        presentation_engine,
    );
    let server = Server::new(&config, service).await.unwrap();
    let port = server.port();
    tokio::spawn(server.run());

    TestServer {
        base_url: format!("http://{}:{}", config.server.host, port),
        credential_repo,
    }
}

/// Build a `Config` suitable for integration tests.
///
/// Binds to port 0 (OS-assigned) and disables the system proxy so tests are
/// fully self-contained.
pub fn make_config() -> Config {
    let mut config = Config::load().unwrap();
    config.server.host = "localhost".to_string();
    config.server.port = 0;
    config.oid4vci.use_system_proxy = false;
    config
}

/// Generates a fresh P-256 key pair at runtime.
///
/// Returns an [`EncodingKey`] for signing JWTs and the matching public JWK
/// value for embedding in the JWT header (so the auth middleware can verify).
pub fn create_test_keypair() -> (EncodingKey, serde_json::Value) {
    let key_pair = KeyPair::generate(Curve::P256).expect("P-256 key generation should not fail");

    let encoding_key = EncodingKey::from_ec_der(key_pair.to_pkcs8_der());

    let crypto_jwk = Jwk::try_from(&key_pair).expect("P-256 key pair should convert to JWK");
    let jwk = serde_json::to_value(&crypto_jwk).expect("JWK should serialize to JSON");

    (encoding_key, jwk)
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
