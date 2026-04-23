use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::domain::service::Service;
use cloud_identity_wallet::outbound::MemoryTenantRepository;
use cloud_identity_wallet::server::Server;
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

    // Create tenant repository based on database URL
    let tenant_repo = MemoryTenantRepository::new();

    // Create service and server
    let service = Service::new(tenant_repo);
    let server = Server::new(&config, service).await?;
    server.run().await
}
