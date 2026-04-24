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
///
/// Provides the three components of an HTTP error response:
/// - The HTTP status code
/// - The machine-readable error code
/// - An optional human-readable description
pub trait IntoApiError {
    fn status(&self) -> StatusCode;
    fn error_code(&self) -> &'static str;
    fn error_description(&self) -> Option<String>;
}

/// Blanket impl: any type implementing `IntoApiError` converts to `ApiError`
/// automatically.
impl<E: IntoApiError> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError {
            status: e.status(),
            error: e.error_code(),
            error_description: e.error_description(),
        }
    }
}

impl IntoApiError for TenantError {
    fn status(&self) -> StatusCode {
        match self {
            TenantError::InvalidName(_) => StatusCode::BAD_REQUEST,
            TenantError::Backend(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            TenantError::InvalidName(_) => "invalid_request",
            TenantError::Backend(_) => "internal_error",
        }
    }

    fn error_description(&self) -> Option<String> {
        match self {
            TenantError::InvalidName(msg) => Some(msg.clone()),
            TenantError::Backend(_) => {
                Some("An internal error occurred while processing your request".into())
            }
        }
    }
}
