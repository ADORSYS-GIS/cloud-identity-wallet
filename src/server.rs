mod auth;
pub(crate) mod error;
mod handlers;
mod responses;

use std::sync::Arc;

use crate::config::Config;
use crate::domain::service::Service;
use crate::server::auth::auth;
use crate::server::handlers::{get_session_events, health_check, home, register_tenant};
use crate::session::SessionStore;

use axum::http::Method;
use axum::{
    Router,
    routing::{get, post},
};
use color_eyre::eyre::{Context, Result};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Debug)]
/// The global application state shared between all request handlers.
pub(crate) struct AppState<S: SessionStore> {
    service: Arc<Service<S>>,
}

// We manually implement Clone here to avoid bounds on generic types
impl<S: SessionStore> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    /// Creates a new HTTPS server.
    pub async fn new<S: SessionStore + Clone>(
        config: &Config,
        service: Service<S>,
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
            service: Arc::new(service),
        };

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1", api_routes())
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

fn api_routes<S: SessionStore + Clone>() -> Router<AppState<S>> {
    // Public routes (no authentication required)
    let public_routes = Router::new().route("/tenants", post(register_tenant));

    // Private routes (authentication required)
    let private_routes = Router::new()
        .route("/issuance/{session_id}/events", get(get_session_events))
        .layer(axum::middleware::from_fn(auth));

    public_routes.merge(private_routes)
}
