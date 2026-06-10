use reqwest::header::CONTENT_TYPE;
use reqwest_middleware::ClientWithMiddleware;
use url::Url;

use crate::oid4vp::{
    authorization::{AuthorizationResponse, DirectPostResponse},
    response_mode::error::DirectPostError,
};

const FORM_ENCODED_HEADER: &str = "application/x-www-form-urlencoded";

/// Result of a `direct_post` submission to the Verifier's `response_uri`.
///
/// The Verifier may optionally return a `redirect_uri` that the Wallet can use
/// to redirect the user back after processing the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPostResult {
    /// Optional redirect URI from the Verifier's response.
    pub redirect_uri: Option<Url>,
}

/// Sends an Authorization Response via `direct_post` to the Verifier's `response_uri`.
///
/// Per [OpenID4VP §8.2], the Wallet POSTs the Authorization Response parameters
/// as `application/x-www-form-urlencoded` to the `response_uri`. The Verifier may
/// respond with a JSON body containing an optional `redirect_uri`.
///
/// # Security
///
/// - `response_uri` is validated to use HTTPS.
/// - `response_uri` is validated against `expected_response_uri` from the
///   original Authorization Request to prevent SSRF.
/// - The HTTP client MUST be configured not to follow redirects.
///
/// [OpenID4VP §8.2]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2
pub async fn send_direct_post(
    http_client: &ClientWithMiddleware,
    response_uri: &Url,
    expected_response_uri: &Url,
    response: &AuthorizationResponse,
) -> Result<DirectPostResult, DirectPostError> {
    validate_response_uri(response_uri, expected_response_uri)?;
    execute_direct_post(http_client, response_uri, response).await
}

async fn execute_direct_post(
    http_client: &ClientWithMiddleware,
    response_uri: &Url,
    response: &AuthorizationResponse,
) -> Result<DirectPostResult, DirectPostError> {
    let body = serde_urlencoded::to_string(response.as_direct_post_form())
        .map_err(|e| DirectPostError::HttpRequestFailed(format!("serialization failed: {e}")))?;

    let http_response = http_client
        .post(response_uri.as_str())
        .header(CONTENT_TYPE, FORM_ENCODED_HEADER)
        .body(body)
        .send()
        .await
        .map_err(|e| DirectPostError::HttpRequestFailed(e.to_string()))?;

    let status = http_response.status();

    if status.is_success() {
        let body_text = http_response
            .text()
            .await
            .map_err(|e| DirectPostError::HttpRequestFailed(e.to_string()))?;

        if body_text.trim().is_empty() {
            return Ok(DirectPostResult { redirect_uri: None });
        }

        let parsed: DirectPostResponse = serde_json::from_str(&body_text)
            .map_err(|e| DirectPostError::ResponseParseError(e.to_string()))?;

        Ok(DirectPostResult {
            redirect_uri: parsed.redirect_uri,
        })
    } else {
        let body_text = http_response.text().await.unwrap_or_default();

        Err(DirectPostError::HttpError {
            status: status.as_u16(),
            body: body_text,
        })
    }
}

fn validate_response_uri(
    response_uri: &Url,
    expected_response_uri: &Url,
) -> Result<(), DirectPostError> {
    if response_uri.scheme() != "https" {
        return Err(DirectPostError::HttpsRequired);
    }

    if response_uri != expected_response_uri {
        return Err(DirectPostError::UriMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::oid4vp::authorization::{AuthorizationResponse, Presentation, VpToken};
    use crate::oid4vp::error::AuthorizationErrorCode;

    fn test_http_client() -> ClientWithMiddleware {
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("valid client");
        ClientBuilder::new(inner).build()
    }

    fn vp_token() -> VpToken {
        let mut entries = BTreeMap::new();
        entries.insert(
            "pid".to_string(),
            vec![Presentation::String("eyJhbGciOiJFUzI1NiJ9...".to_string())],
        );
        VpToken::new(entries).unwrap()
    }

    #[tokio::test]
    async fn successful_direct_post_with_redirect_uri() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("vp_token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"redirect_uri": "https://client.example.org/cb"})),
            )
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token()).with_state("state-123");
        let result = execute_direct_post(&client, &uri, &response)
            .await
            .expect("success");

        assert_eq!(
            result.redirect_uri,
            Some(Url::parse("https://client.example.org/cb").unwrap())
        );
    }

    #[tokio::test]
    async fn successful_direct_post_without_redirect_uri() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token()).with_state("state-123");
        let result = execute_direct_post(&client, &uri, &response)
            .await
            .expect("success");

        assert!(result.redirect_uri.is_none());
    }

    #[tokio::test]
    async fn successful_direct_post_with_empty_body() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token()).with_state("state-123");
        let result = execute_direct_post(&client, &uri, &response)
            .await
            .expect("success");

        assert!(result.redirect_uri.is_none());
    }

    #[tokio::test]
    async fn sends_error_response_via_direct_post() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("error=access_denied"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response =
            AuthorizationResponse::error(AuthorizationErrorCode::AccessDenied).with_state("xyz");
        let result = execute_direct_post(&client, &uri, &response)
            .await
            .expect("success");

        assert!(result.redirect_uri.is_none());
    }

    #[tokio::test]
    async fn http_error_response() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token());
        let err = execute_direct_post(&client, &uri, &response)
            .await
            .unwrap_err();

        assert_eq!(
            err,
            DirectPostError::HttpError {
                status: 500,
                body: "internal error".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn does_not_follow_redirects() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .respond_with(
                ResponseTemplate::new(302).append_header("location", "https://evil.example.com"),
            )
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token());
        let err = execute_direct_post(&client, &uri, &response)
            .await
            .unwrap_err();

        assert_eq!(
            err,
            DirectPostError::HttpError {
                status: 302,
                body: "".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn serialization_format_validation() {
        let mock_server = MockServer::start().await;
        let uri = Url::parse(&format!("{}/response", mock_server.uri())).unwrap();

        Mock::given(method("POST"))
            .and(path("/response"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("vp_token="))
            .and(body_string_contains("state=state-123"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let client = test_http_client();
        let response = AuthorizationResponse::new(vp_token()).with_state("state-123");
        let result = execute_direct_post(&client, &uri, &response)
            .await
            .expect("success");

        assert!(result.redirect_uri.is_none());
    }

    #[test]
    fn rejects_non_https_response_uri() {
        let uri = Url::parse("http://verifier.example.com/response").unwrap();
        let expected = Url::parse("http://verifier.example.com/response").unwrap();
        let err = validate_response_uri(&uri, &expected).unwrap_err();
        assert_eq!(err, DirectPostError::HttpsRequired);
    }

    #[test]
    fn rejects_mismatched_response_uri() {
        let uri = Url::parse("https://verifier.example.com/response").unwrap();
        let expected = Url::parse("https://verifier.example.com/other").unwrap();
        let err = validate_response_uri(&uri, &expected).unwrap_err();
        assert_eq!(err, DirectPostError::UriMismatch);
    }

    #[test]
    fn accepts_matching_https_response_uri() {
        let uri = Url::parse("https://verifier.example.com/response").unwrap();
        assert!(validate_response_uri(&uri, &uri).is_ok());
    }
}
