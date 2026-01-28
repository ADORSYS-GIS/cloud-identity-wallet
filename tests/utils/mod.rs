use cloud_identity_wallet::{config::Config, server::Server};

pub async fn spawn_server() -> String {
    let config = {
        let mut config = Config::load().unwrap();
        config.server.host = "localhost".to_string();
        config.server.port = 0;
        config
    };

    let server = Server::new(&config).await.unwrap();

    let port = server.port();
    tokio::spawn(server.run());

    format!("http://{}:{}", config.server.host, port)
}
