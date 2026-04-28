use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::domain::models::tenants::TenantError;

/// The unified error type used by all HTTP handlers.
///
/// Implements `IntoResponse` to serialize as JSON with the standard shape.
/// All domain errors convert into this type via `From` impls.
/// ```json
/// {
///   "error": "string",
///   "error_description": "string (optional)"
/// }
/// ```
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status code.
    pub status: StatusCode,
    /// Machine-readable error code (snake_case ASCII).
    pub error: &'static str,
    /// Optional human-readable description. Omitted from JSON when None.
    pub error_description: Option<String>,
}

impl ApiError {
    /// Log `source` at ERROR level and return a generic 500 response.
    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal server error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "internal_error",
            error_description: Some("The server encountered an unexpected error.".into()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body<'a> {
            error: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            error_description: Option<&'a str>,
        }

        let body = Body {
            error: self.error,
            error_description: self.error_description.as_deref(),
        };

        (self.status, Json(body)).into_response()
    }
}

/// Implemented by every domain error type that can be returned from an API handler.
pub trait IntoApiError {
    fn into_api_error(self) -> ApiError;
}

/// Blanket impl: any type implementing `IntoApiError` converts to `ApiError`
/// automatically.
impl<E: IntoApiError> From<E> for ApiError {
    fn from(e: E) -> Self {
        e.into_api_error()
    }
}

impl IntoApiError for TenantError {
    fn into_api_error(self) -> ApiError {
        match self {
            TenantError::InvalidName(msg) => ApiError {
                status: StatusCode::BAD_REQUEST,
                error: "invalid_request",
                error_description: Some(msg),
            },
            TenantError::Backend(src) => ApiError::internal(src),
        }
    }
}
