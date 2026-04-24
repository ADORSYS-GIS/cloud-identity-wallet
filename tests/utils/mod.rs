use cloud_identity_wallet::{
    config::Config, domain::service::Service, outbound::SqlTenantRepository, server::Server,
    session::MemorySession,
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
    let session_store = MemorySession::default();

    let service = Service::new(session_store, tenant_repo);
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}
