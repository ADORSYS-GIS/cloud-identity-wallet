use cloud_identity_wallet::{
    config::Config, domain::service::Service, server::Server, session::MemorySession,
};

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let session_store = MemorySession::default();
    let service = Service::new(session_store);
    let server = Server::new(&config, service).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}
