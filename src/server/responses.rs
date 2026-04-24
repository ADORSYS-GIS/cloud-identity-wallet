use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Generic response structure shared by all API success responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseBody<T: Serialize> {
    status_code: StatusCode,
    data: T,
}

impl<T: Serialize> ResponseBody<T> {
    /// Creates a new response body with the given status code and data.
    pub fn new(status_code: StatusCode, data: T) -> Self {
        Self { status_code, data }
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status_code
    }

    /// Consumes the response body and returns the data.
    pub fn into_data(self) -> T {
        self.data
    }
}

impl<T: Serialize> IntoResponse for ResponseBody<T> {
    fn into_response(self) -> Response {
        let status = self.status();
        (status, Json(self.into_data())).into_response()
    }
}
