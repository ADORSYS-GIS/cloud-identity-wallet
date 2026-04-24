use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::domain::service::Service;
use cloud_identity_wallet::issuance::AuthorizationUrlBuilder;
use cloud_identity_wallet::outbound::MemoryTenantRepository;
use cloud_identity_wallet::server::Server;
use cloud_identity_wallet::server::sse::SseEvent;
use cloud_identity_wallet::session::MemorySession;
use cloud_identity_wallet::telemetry;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create session store
    // TODO: Replace with Redis session store when ready
    let session_store = MemorySession::default();

    // Create tenant repository
    // TODO: Replace with actual database repository when ready
    let tenant_repo = MemoryTenantRepository::new();

    // Create SSE broadcast channel
    let (sse_broadcast, _) = tokio::sync::broadcast::channel::<SseEvent>(16);

    // Create HTTP client and authorization URL builder
    let http_client = cloud_wallet_openid4vc::http::HttpClientBuilder::new()
        .build()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create HTTP client: {e}"))?;

    let authz_url_builder = AuthorizationUrlBuilder::new(
        config.wallet.client_id.clone(),
        config.wallet.redirect_uri.clone(),
        http_client,
    );

    // Create service and server
    let service = Service::new(session_store, tenant_repo, authz_url_builder, sse_broadcast);
    let server = Server::new(&config, service).await?;
    server.run().await
}
