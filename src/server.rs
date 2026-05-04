mod auth;
mod error;
mod handlers;
mod responses;

use std::sync::Arc;

use crate::config::Config;
use crate::domain::service::Service;
use crate::server::handlers::{health_check, home, register_tenant, start_issuance};
use crate::session::SessionStore;

use axum::http::Method;
use axum::{
    Router,
    body::Body,
    extract::Request,
    middleware::Next,
    response::IntoResponse,
    routing::{get, post},
};
use color_eyre::eyre::{Context, Result};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

#[derive(Debug)]
/// The global application state shared between all request handlers.
struct AppState<S: SessionStore> {
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

/// Middleware that injects a nil UUID as tenant_id for testing purposes.
/// This bypasses the auth middleware and should only be used in test environments.
async fn test_tenant_bypass(request: Request<Body>, next: Next) -> impl IntoResponse {
    let test_tenant_id = Uuid::nil();
    let mut request = request;
    request.extensions_mut().insert(test_tenant_id);
    next.run(request).await
}

impl Server {
    /// Creates a new HTTPS server.
    pub async fn new<S: SessionStore>(config: &Config, service: Service<S>) -> Result<Self> {
        Self::new_with_test_bypass(config, service, false).await
    }

    /// Creates a new server, optionally with test tenant bypass middleware.
    pub async fn new_with_test_bypass<S: SessionStore>(
        config: &Config,
        service: Service<S>,
        enable_test_bypass: bool,
    ) -> Result<Self> {
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

        let state = AppState {
            service: Arc::new(service),
        };

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1", api_routes(enable_test_bypass))
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

fn api_routes<S: SessionStore>(enable_test_bypass: bool) -> Router<AppState<S>> {
    let public_routes = Router::new().route("/tenants", post(register_tenant));

    let protected_routes = create_protected_routes::<S>(enable_test_bypass);

    Router::new()
        .merge(public_routes)
        .nest("/protected", protected_routes)
}

/// Creates the protected routes router with authentication middleware.
///
/// All routes under this router require authentication. The middleware
/// extracts tenant_id from JWT claims and injects it into request extensions.
fn create_protected_routes<S: SessionStore>(enable_test_bypass: bool) -> Router<AppState<S>> {
    let issuance_routes = Router::new().route("/issuance/start", post(start_issuance));

    if enable_test_bypass {
        issuance_routes.layer(axum::middleware::from_fn(test_tenant_bypass))
    } else {
        issuance_routes.layer(axum::middleware::from_fn(auth::auth))
    }
}
