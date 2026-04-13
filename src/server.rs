mod auth;
mod error;
mod handlers;
mod responses;

use crate::config::Config;
use crate::server::auth::AuthenticatedUser;
use crate::server::handlers::{health_check, home};
use axum::extract::FromRef;
use axum::http::Method;
use axum::{Json, Router, routing::get};
use color_eyre::eyre::{Context, Result};
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

pub use auth::generate_token;
pub use error::ApiError;

#[derive(Debug, Clone)]
pub struct AppState {
    jwt: crate::config::JwtConfig,
}

impl FromRef<AppState> for crate::config::JwtConfig {
    fn from_ref(state: &AppState) -> Self {
        state.jwt.clone()
    }
}

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

        let state = AppState {
            jwt: config.jwt.clone(),
        };

        let api_routes = Router::new()
            .route("/protected", get(|user: AuthenticatedUser| async move {
                Json(json!({
                    "message": "Protected endpoint",
                    "tenant_id": user.tenant_id()
                }))
            }));

        let router = Router::new()
            .route("/", get(home))
            .route("/health", get(health_check))
            .nest("/api/v1", api_routes)
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
