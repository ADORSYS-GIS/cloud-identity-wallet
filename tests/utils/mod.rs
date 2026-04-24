use cloud_identity_wallet::{
    config::Config,
    domain::service::Service,
    issuance::AuthorizationUrlBuilder,
    outbound::{MemorySessionRepository, SqlTenantRepository},
    server::{sse::SseEvent, Server},
};

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

    // Create session repository and SSE broadcast
    let session_repo = MemorySessionRepository::new();
    let (sse_broadcast, _) = tokio::sync::broadcast::channel::<SseEvent>(16);

    // Create HTTP client and authorization URL builder
    let http_client = cloud_wallet_openid4vc::http::HttpClientBuilder::new()
        .allow_http_urls(true)
        .build()
        .unwrap();
    let authz_url_builder = AuthorizationUrlBuilder::new(
        config.wallet.client_id.clone(),
        config.wallet.redirect_uri.clone(),
        http_client,
    );

    let service = Service::new(tenant_repo, session_repo, authz_url_builder, sse_broadcast);
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}
