mod auth;
mod handlers;
mod responses;
pub mod sse;

use crate::config::Config;
use crate::domain::InMemorySessionStore;
use crate::server::handlers::{cancel_session, health_check, home, submit_tx_code};
use crate::server::sse::SseBroadcaster;

use axum::http::Method;
use axum::{Router, routing::get};
use color_eyre::eyre::{Context, Result};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Debug, Clone)]
/// The global application state shared between all request handlers.
pub struct AppState {
    pub session_store: Arc<dyn crate::domain::SessionStore>,
    pub broadcaster: SseBroadcaster,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    /// Creates a new HTTPS server.
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

        let state = Arc::new(AppState {
            session_store,
            broadcaster,
        });

        let issuance_router = Router::new()
            .route("/{session_id}/tx-code", axum::routing::post(submit_tx_code))
            .route("/{session_id}/cancel", axum::routing::post(cancel_session));

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1/issuance", issuance_router)
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

    /// Runs the HTTP server.
    pub async fn run(self) -> Result<()> {
        tracing::info!("Server listening on {}", self.listener.local_addr()?);
        axum::serve(self.listener, self.router).await?;
        Ok(())
    }
}
