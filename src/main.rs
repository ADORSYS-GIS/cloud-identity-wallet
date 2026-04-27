use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::domain::service::Service;
use cloud_identity_wallet::outbound::MemoryTenantRepository;
use cloud_identity_wallet::server::Server;
use cloud_identity_wallet::server::sse::SseEvent;
use cloud_identity_wallet::session::MemorySession;
use cloud_identity_wallet::telemetry;
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciConfig, Oid4vciClient};

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

    // Create OID4VCI client
    let oid4vci_config = Oid4vciConfig::new(
        config.wallet.client_id.clone(),
        config.wallet.redirect_uri.clone(),
    );
    let oid4vci_client = Oid4vciClient::new(oid4vci_config)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create OID4VCI client: {e}"))?;

    // Create service and server
    let service = Service::new(session_store, tenant_repo, oid4vci_client, sse_broadcast);
    let server = Server::new(&config, service).await?;
    server.run().await
}
