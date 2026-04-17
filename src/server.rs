mod handlers;
mod responses;
pub mod sse;

use crate::config::Config;
use crate::domain::InMemorySessionStore;
use crate::server::handlers::{IssuanceState, cancel_session, health_check, home, submit_tx_code};
use crate::server::sse::SseBroadcaster;

use axum::http::Method;
use axum::{Router, routing::get, routing::post};
use color_eyre::eyre::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    pub async fn new(config: &Config) -> Result<Self> {
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &'_ axum::extract::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = %request.method(), uri)
            });

        let cors_layer = CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        let session_store = Arc::new(InMemorySessionStore::new());
        let broadcaster = SseBroadcaster::new();

        let state = Arc::new(IssuanceState {
            session_store,
            broadcaster,
        });

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .route(
                "/api/v1/issuance/{session_id}/tx-code",
                post(submit_tx_code),
            )
            .route("/api/v1/issuance/{session_id}/cancel", post(cancel_session))
            .layer(cors_layer)
            .layer(trace_layer)
            .with_state(state);

        let listener = TcpListener::bind(format!("{}:{}", config.server.host, config.server.port))
            .await
            .wrap_err_with(|| format!("Failed to bind to port {}", config.server.port))?;

        Ok(Self { router, listener })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    pub async fn run(self) -> Result<()> {
        tracing::info!("Server listening on {}", self.listener.local_addr()?);
        axum::serve(self.listener, self.router).await?;
        Ok(())
    }
}
