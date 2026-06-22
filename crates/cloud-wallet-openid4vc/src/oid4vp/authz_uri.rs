//! Authorization Request URI parsing for OpenID4VP.
//!
//! This module provides URI parsing for OpenID4VP authorization requests,
//! supporting both `openid4vp://` (OpenID4VP standard) and `haip-vp://`
//! (HAIP §5.1 alternative) schemes.
//!
//! # Spec References
//!
//! - [OpenID4VP §5 Authorization Request](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request)
//! - [HAIP §5.1 OpenID4VP via Redirects](https://openid.net/specs/oauth-2-0-for-first-party-mobile-apps-1_0.html#name-openid4vp-via-redirects)

use url::Url;

use crate::errors::{Error, ErrorKind};

/// Parses an authorization request URI into its raw query string form.
///
/// This function normalizes the URI scheme and extracts the query parameters
/// for further processing by the OID4VP client.
pub fn parse_authz_uri(uri: &str) -> Result<String, Error> {
    let parsed_url = match Url::parse(uri) {
        Ok(url) => url,
        Err(e) => {
            return Err(Error::message(
                ErrorKind::InvalidPresentationRequest,
                format!("invalid authorization request URI: {e}"),
            ));
        }
    };

    let scheme = parsed_url.scheme();
    let scheme_lower = scheme.to_lowercase();
    if !matches!(scheme_lower.as_str(), "openid4vp" | "haip-vp") {
        return Err(Error::message(
            ErrorKind::InvalidPresentationRequest,
            format!("unsupported scheme '{scheme}'; expected 'openid4vp' or 'haip-vp'"),
        ));
    }

    let query = parsed_url
        .query()
        .ok_or_else(|| {
            Error::message(
                ErrorKind::InvalidPresentationRequest,
                "authorization request URI has no query parameters",
            )
        })?
        .to_string();

    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_openid4vp_uri() {
        let uri = "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example.com%2Fcb&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest";
        let query = parse_authz_uri(uri).expect("should parse openid4vp URI");
        assert!(query.contains("client_id="));
        assert!(query.contains("request_uri="));
    }

    #[test]
    fn parse_haip_vp_uri() {
        let uri = "haip-vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example.com%2Fcb&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest";
        let query = parse_authz_uri(uri).expect("should parse haip-vp URI");
        assert!(query.contains("client_id="));
        assert!(query.contains("request_uri="));
    }

    #[test]
    fn parse_haip_vp_case_insensitive() {
        let uri = "HAIP-VP://?client_id=test";
        let query = parse_authz_uri(uri).expect("should parse HAIP-VP URI");
        assert!(query.contains("client_id="));
    }

    #[test]
    fn parse_openid4vp_case_insensitive() {
        let uri = "OPENID4VP://?client_id=test";
        let query = parse_authz_uri(uri).expect("should parse OPENID4VP URI");
        assert!(query.contains("client_id="));
    }

    #[test]
    fn reject_unsupported_scheme() {
        let uri = "https://example.com/auth?client_id=test";
        let result = parse_authz_uri(uri);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn reject_rejects_http_scheme() {
        let uri = "http://example.com/auth?client_id=test";
        let result = parse_authz_uri(uri);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn reject_malformed_uri() {
        let uri = "not a valid uri at :: all";
        let result = parse_authz_uri(uri);
        assert!(result.is_err());
    }

    #[test]
    fn reject_uri_without_query() {
        let uri = "openid4vp://";
        let result = parse_authz_uri(uri);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("no query parameters"));
    }

    #[test]
    fn preserves_special_characters_in_query() {
        let uri = "haip-vp://?client_id=x509_san_dns%3Averifier.example.com&nonce=abc-123_test";
        let query = parse_authz_uri(uri).expect("should parse URI");
        assert!(query.contains("x509_san_dns%3Averifier.example.com"));
        assert!(query.contains("nonce=abc-123_test"));
    }
}
