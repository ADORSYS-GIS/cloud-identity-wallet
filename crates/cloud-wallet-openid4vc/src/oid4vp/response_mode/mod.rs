mod direct_post;
mod direct_post_jwt;
mod error;

pub use direct_post::send_direct_post;
pub use direct_post_jwt::{encrypt_authorization_response, send_direct_post_jwt};
pub use error::{DirectPostError, JarmEncryptError};

use url::Url;

use crate::oid4vp::authorization::DirectPostResponse;

/// Validates that `response_uri` is safe to POST an Authorization Response to.
///
/// Enforced by both `direct_post` and `direct_post.jwt` response modes:
/// - The URI must use HTTPS (prevents plaintext leakage).
/// - The URI must match `expected_response_uri` from the original Authorization
///   Request (prevents SSRF substitution attacks).
pub(super) fn validate_response_uri(
    response_uri: &Url,
    expected_response_uri: &Url,
) -> Result<(), DirectPostError> {
    if response_uri.scheme() != "https" {
        #[cfg(not(test))]
        return Err(DirectPostError::HttpsRequired);

        #[cfg(test)]
        if response_uri.host_str() != Some("127.0.0.1")
            && response_uri.host_str() != Some("localhost")
        {
            return Err(DirectPostError::HttpsRequired);
        }
    }

    if response_uri != expected_response_uri {
        return Err(DirectPostError::UriMismatch);
    }

    Ok(())
}

/// Parses a Verifier HTTP response into a [`DirectPostResponse`].
///
/// Shared by both `direct_post` and `direct_post.jwt` response modes — the
/// Verifier response format (§8.2 / §8.3.1) is the same regardless of how
/// the Authorization Response was transported.
pub(super) async fn parse_verifier_response(
    http_response: reqwest::Response,
) -> Result<DirectPostResponse, DirectPostError> {
    let status = http_response.status();

    if status == reqwest::StatusCode::OK {
        let content_type = http_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref ct) = content_type
            && !is_json_content_type(ct)
        {
            return Err(DirectPostError::ResponseParseError(format!(
                "expected application/json response, got content-type: {content_type:?}"
            )));
        }

        let body_bytes = http_response
            .bytes()
            .await
            .map_err(|e| DirectPostError::HttpRequestFailed(e.to_string()))?;

        if body_bytes.is_empty() {
            return Ok(DirectPostResponse { redirect_uri: None });
        }

        let parsed: DirectPostResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| DirectPostError::ResponseParseError(e.to_string()))?;
        Ok(parsed)
    } else {
        let body_text = http_response.text().await.unwrap_or_default();
        let status = status.as_u16();

        if status >= 500 {
            Err(DirectPostError::HttpServerError {
                status,
                body: body_text,
            })
        } else if (300..400).contains(&status) {
            Err(DirectPostError::RedirectNotFollowed { status })
        } else {
            Err(DirectPostError::VerifierError {
                status,
                body: body_text,
            })
        }
    }
}

/// Checks whether a `Content-Type` header value is `application/json`,
/// ignoring ASCII case and any parameters after `;`.
fn is_json_content_type(value: &str) -> bool {
    let (media_type, _rest) = value.split_once(';').unwrap_or((value, ""));
    media_type.trim().eq_ignore_ascii_case("application/json")
}
