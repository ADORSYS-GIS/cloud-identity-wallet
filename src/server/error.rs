use std::borrow::Cow;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::domain::models::consent::ConsentError;
use crate::domain::models::issuance::{IssuanceError, IssuanceErrorCode};
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
    pub error: Cow<'static, str>,
    /// Optional human-readable description. Omitted from JSON when None.
    pub error_description: Option<String>,
}

impl ApiError {
    /// Log `source` at ERROR level and return a generic 500 response.
    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal server error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: Cow::Borrowed("internal_error"),
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
            error: self.error.as_ref(),
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
                error: Cow::Borrowed("invalid_request"),
                error_description: Some(msg),
            },
            TenantError::NotFound { .. } => ApiError {
                status: StatusCode::NOT_FOUND,
                error: Cow::Borrowed("not_found"),
                error_description: Some("Tenant not found.".into()),
            },
            TenantError::InvalidData(msg) => ApiError::internal(msg),
            TenantError::Backend(src) => ApiError::internal(src),
            TenantError::Encryption(src) => ApiError::internal(src),
        }
    }
}

impl IntoApiError for IssuanceError {
    fn into_api_error(self) -> ApiError {
        let status = match &self.error {
            IssuanceErrorCode::InvalidCredentialOffer => StatusCode::BAD_REQUEST,
            IssuanceErrorCode::IssuerMetadataFetchFailed => StatusCode::BAD_GATEWAY,
            IssuanceErrorCode::AuthServerMetadataFetchFailed => StatusCode::BAD_GATEWAY,
            IssuanceErrorCode::SessionNotFound => StatusCode::NOT_FOUND,
            IssuanceErrorCode::InvalidSessionState => StatusCode::CONFLICT,
            IssuanceErrorCode::InvalidTxCode => StatusCode::BAD_REQUEST,
            IssuanceErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            IssuanceErrorCode::CredentialNotFound => StatusCode::NOT_FOUND,
            IssuanceErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            IssuanceErrorCode::Cancelled => StatusCode::CONFLICT,
            IssuanceErrorCode::External(_) => StatusCode::BAD_GATEWAY,
        };

        ApiError {
            status,
            error: self.error.to_string().into(),
            error_description: self.error_description,
        }
    }
}

impl IntoApiError for ConsentError {
    fn into_api_error(self) -> ApiError {
        match self {
            ConsentError::NotFound(session_id) => ApiError {
                status: StatusCode::NOT_FOUND,
                error: Cow::Borrowed("session_not_found"),
                error_description: Some(format!("Session {} does not exist", session_id)),
            },
            ConsentError::InvalidState => ApiError {
                status: StatusCode::CONFLICT,
                error: Cow::Borrowed("invalid_session_state"),
                error_description: Some("Session is not in awaiting_consent state".into()),
            },
            ConsentError::AuthorizationUrlFailed(msg) => ApiError {
                status: StatusCode::BAD_GATEWAY,
                error: Cow::Borrowed("bad_gateway"),
                error_description: Some(msg),
            },
            ConsentError::Storage(err) => ApiError::internal(err),
            ConsentError::EventPublishing(msg) => {
                tracing::warn!("Event publishing failed: {}", msg);
                // Event publishing failures are not critical, so we don't return an error to the client
                ApiError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: Cow::Borrowed("internal_error"),
                    error_description: Some(msg),
                }
            }
        }
    }
}
