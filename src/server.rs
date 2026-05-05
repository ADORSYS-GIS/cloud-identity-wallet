mod auth;
pub(crate) mod error;
mod handlers;
mod responses;
pub mod sse;

use std::sync::Arc;

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::server::handlers::{
    cancel_session, health_check, home, register_tenant, submit_tx_code,
};
use crate::server::sse::SseBroadcaster;
use crate::session::{MemorySession, SessionStore};

use axum::Router;
use axum::http::Method;
use axum::routing::get;
use color_eyre::eyre::{Context, Result};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Clone)]
/// The global application state shared between all request handlers.
pub(crate) struct AppState<S: SessionStore + Clone> {
    pub issuance_store: Arc<S>,
    pub tenant_repo: Arc<dyn TenantRepo>,
    pub broadcaster: SseBroadcaster,
    pub issuance_engine: IssuanceEngine,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    /// Creates a new HTTPS server with default in-memory stores.
    pub async fn new(config: &Config, engine: IssuanceEngine) -> Result<Self> {
        let session_store = MemorySession::default();
        let tenant_repo = Arc::new(crate::outbound::MemoryTenantRepo::new());
        let broadcaster = SseBroadcaster::new();

        Self::with_stores(config, session_store, tenant_repo, broadcaster, engine).await
    }

    /// Creates a new HTTPS server with the provided stores.
    pub async fn with_stores<S: SessionStore + Clone>(
        config: &Config,
        session_store: S,
        tenant_repo: Arc<dyn TenantRepo>,
        broadcaster: SseBroadcaster,
        issuance_engine: IssuanceEngine,
    ) -> Result<Self> {
        let trace_layer =
            TraceLayer::new_for_http().make_span_with(|request: &'_ axum::extract::Request<_>| {
                let uri = request.uri().to_string();
                tracing::info_span!("request", method = %request.method(), uri)
            });

        let cors_layer = CorsLayer::new()
            // TODO : Replace Any with specific origins
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ]);

        let state = AppState {
            issuance_store: Arc::new(session_store),
            tenant_repo,
            broadcaster,
            issuance_engine,
        };

        let issuance_router = Router::new()
            .route("/{session_id}/tx-code", axum::routing::post(submit_tx_code))
            .route("/{session_id}/cancel", axum::routing::post(cancel_session));

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1/issuance", issuance_router)
            .route("/api/v1/tenants", axum::routing::post(register_tenant))
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
