use axum::http::StatusCode;

use crate::server::responses::ResponseBody;

/// Health check endpoint.
///
/// Returns a simple 200 OK response to indicate the service is running.
pub async fn health_check() -> ResponseBody<&'static str> {
    ResponseBody::new(StatusCode::OK, "OK")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_data(), "OK");
    }
}
