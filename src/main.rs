use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::outbound::MemoryTenantRepo;
use cloud_identity_wallet::server::Server;
use cloud_identity_wallet::session::MemorySession;
use cloud_identity_wallet::setup;
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

    // TODO: Replace these later on
    let session_store = MemorySession::default();
    let tenant_repo = MemoryTenantRepo::new();

    let service = setup::build_service(session_store, tenant_repo, &config)?;
    let server = Server::new(&config, service).await?;
    server.run().await
}
