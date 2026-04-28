use cloud_identity_wallet::{config::Config, domain::InMemorySessionStore, outbound::MemoryTenantRepository, server::Server, server::sse::SseBroadcaster};
use std::sync::Arc;

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let issuance_store = Arc::new(InMemorySessionStore::new());
    let tenant_repo = Arc::new(MemoryTenantRepository::new());
    let broadcaster = SseBroadcaster::new();

    let server = Server::with_stores(&config, issuance_store, tenant_repo, broadcaster)
        .await
        .unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}
