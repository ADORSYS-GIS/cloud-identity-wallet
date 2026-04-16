use axum::{Json, http::StatusCode, response::IntoResponse};
use jsonwebtoken::errors::Error as JwtError;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Missing or invalid Authorization header")]
    InvalidAuthorizationHeader,
    #[error("Public key JWK not found in token header")]
    MissingKey,
    #[error("{0}")]
    JwtError(#[from] JwtError),
    #[error("Internal server error")]
    InternalServer,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AuthError::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        };

        let body = json!({
            "error": "unauthorized",
            "error_description": self.to_string()
        });

        (status, Json(body)).into_response()
    }
}
