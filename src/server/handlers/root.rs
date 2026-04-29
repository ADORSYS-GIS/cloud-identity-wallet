use axum::http::StatusCode;

use crate::server::responses::ResponseBody;

/// Home/root endpoint.
///
/// Returns a simple welcome message indicating the service identity.
pub async fn home() -> ResponseBody<&'static str> {
    ResponseBody::new(StatusCode::OK, "Cloud Identity Wallet")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_home() {
        let response = home().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_data(), "Cloud Identity Wallet");
    }
}
