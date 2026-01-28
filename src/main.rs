use cloud_identity_wallet::config::Config;
use cloud_identity_wallet::server::Server;
use cloud_identity_wallet::telemetry;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    telemetry::init_tracing();

    // Load configuration
    let config = Config::load()?;
    tracing::info!("Loaded configuration: {:?}", config);

    // Create and run server
    let server = Server::new(&config).await?;
    server.run().await
}
