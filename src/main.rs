use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::domain::service::Service;
use cloud_identity_wallet::outbound::SqlTenantRepository;
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

    sqlx::any::install_default_drivers();
    // Create database pool and tenant repository
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await?;
    let tenant_repo = SqlTenantRepository::new(pool);
    tenant_repo.init_schema().await?;

    // Create service and server
    let service = Service::new(tenant_repo);
    let server = Server::new(&config, service).await?;
    server.run().await
}
