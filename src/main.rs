use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::domain::service::Service;
use cloud_identity_wallet::outbound::MemoryTenantRepo;
use cloud_identity_wallet::server::Server;
use cloud_identity_wallet::session::MemorySession;
use cloud_identity_wallet::telemetry;
use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};

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

    // Initialize OID4VCI client
    let oid4vci_config = Oid4vciClientConfig::new(
        &config.oid4vci.client_id,
        config.oid4vci.redirect_uri.clone(),
    );
    let oid4vci_client = Oid4vciClient::new(oid4vci_config)?;

    // TODO: Replace with Redis session store when ready
    let session_store = MemorySession::default();

    // TODO: Replace with actual database repository when ready
    let tenant_repo = MemoryTenantRepo::new();

    // Create service and server
    let service = Service::new(session_store, tenant_repo, oid4vci_client);
    let server = Server::new(&config, service).await?;
    server.run().await
}
