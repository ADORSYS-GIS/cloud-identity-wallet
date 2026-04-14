use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal server error")]
    Internal,

    #[error("Upstream error: {0}")]
    UpstreamError(String),
}

impl ApiError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Internal => "internal_error",
            ApiError::UpstreamError(_) => "upstream_error",
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::UpstreamError(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub fn error_description(&self) -> String {
        match self {
            ApiError::BadRequest(msg) => msg.clone(),
            ApiError::Unauthorized(msg) => msg.clone(),
            ApiError::NotFound(msg) => msg.clone(),
            ApiError::Conflict(msg) => msg.clone(),
            ApiError::Internal => "An internal server error occurred.".to_string(),
            ApiError::UpstreamError(msg) => msg.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();

        if matches!(self, ApiError::Internal) {
            tracing::error!("Internal server error occurred");
        }

        let body = ErrorBody {
            error: error_code,
            error_description: self.error_description(),
        };

        (status, Json(body)).into_response()
    }
}

pub fn unauthorized() -> ApiError {
    ApiError::Unauthorized("Missing or invalid bearer token.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ErrorBodyTest {
        error: String,
        error_description: String,
    }

    #[tokio::test]
    async fn test_unauthorized_serialization() {
        let error = unauthorized();
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let error_body: ErrorBodyTest = serde_json::from_slice(&body).unwrap();

        assert_eq!(error_body.error, "unauthorized");
        assert_eq!(
            error_body.error_description,
            "Missing or invalid bearer token."
        );
    }

    #[tokio::test]
    async fn test_internal_error_doesnt_leak_details() {
        let error = ApiError::Internal;
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let error_body: ErrorBodyTest = serde_json::from_slice(&body).unwrap();

        assert_eq!(error_body.error, "internal_error");
        assert_eq!(
            error_body.error_description,
            "An internal server error occurred."
        );
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(
            ApiError::BadRequest("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::Unauthorized("test".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ApiError::NotFound("test".into()).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiError::Conflict("test".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::Internal.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ApiError::UpstreamError("test".into()).status_code(),
            StatusCode::BAD_GATEWAY
        );
    }
}
