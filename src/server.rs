mod auth;
mod handlers;
mod responses;

use std::sync::Arc;

use crate::config::Config;
use crate::domain::service::Service;
use crate::server::handlers::{health_check, home, register_tenant};

use axum::http::Method;
use axum::{Router, routing::{get, post}};
use color_eyre::eyre::{Context, Result};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

/// The global application state shared between all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// Service for tenant operations.
    pub service: Arc<Service>,
}

pub struct Server {
    router: Router,
    listener: TcpListener,
}

impl Server {
    /// Creates a new HTTP server.
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

        // Install SQLx drivers
        sqlx::any::install_default_drivers();

        // Create database connection pool (SQLite in-memory for now)
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .wrap_err("Failed to connect to database")?;

        // Create tenant repository and initialize schema
        let tenant_repo = Arc::new(crate::outbound::SqlTenantRepository::new(pool));
        tenant_repo
            .init_schema()
            .await
            .wrap_err("Failed to initialize database schema")?;

        let service = Arc::new(Service::new(tenant_repo));
        let state = AppState { service };

        // API v1 routes
        let api_v1 = Router::new()
            .route("/tenants", post(register_tenant));

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1", api_v1)
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
