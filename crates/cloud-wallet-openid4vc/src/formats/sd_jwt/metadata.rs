// TODO : Remove dead code allowance when metadata is used
#![allow(dead_code)]

use std::borrow::Cow;

use cloud_wallet_crypto::jwk::{Jwk, JwkSet};
use reqwest::StatusCode;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use super::SdJwt;

const JWT_VC_ISSUER_WELL_KNOWN: &str = "/.well-known/jwt-vc-issuer";

/// Errors returned while resolving JWT VC Issuer Metadata.
#[derive(Debug, thiserror::Error)]
pub enum IssuerMetadataError {
    /// The issuer identifier is invalid or cannot be used for metadata discovery.
    #[error("invalid JWT VC issuer: {message}")]
    InvalidIssuer { message: Cow<'static, str> },

    /// The metadata document violates SD-JWT VC metadata requirements.
    #[error("invalid JWT VC issuer metadata: {message}")]
    InvalidMetadata { message: Cow<'static, str> },

    /// HTTP transport or non-success response error.
    #[error("JWT VC issuer metadata HTTP error")]
    Http {
        /// Human-readable context for the HTTP failure.
        message: Option<Cow<'static, str>>,
        /// HTTP status code, if a response was received.
        status: Option<u16>,
        /// Response body, if available.
        body: Option<String>,
        /// Underlying transport error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The metadata or JWKS response could not be parsed.
    #[error("invalid JWT VC issuer metadata response: {message}")]
    InvalidResponse {
        /// Human-readable parse failure context.
        message: Cow<'static, str>,
        /// Underlying parse error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

/// JWT VC Issuer Metadata as defined by SD-JWT VC draft section 3.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct IssuerMetadata {
    /// Issuer identifier. This must be identical to the issuer-signed JWT `iss`.
    pub issuer: String,

    /// URL of the issuer's JWK Set document.
    pub jwks_uri: Option<Url>,

    /// Issuer JWK Set embedded by value.
    pub jwks: Option<JwkSet>,
}

impl IssuerMetadata {
    /// Validates issuer metadata against the issuer value from the SD-JWT VC.
    pub fn validate_for_issuer(&self, expected_issuer: &str) -> Result<(), IssuerMetadataError> {
        if self.issuer != expected_issuer {
            return Err(IssuerMetadataError::InvalidMetadata {
                message: format!(
                    "metadata issuer '{}' does not match expected issuer '{}'",
                    self.issuer, expected_issuer
                )
                .into(),
            });
        }

        match (&self.jwks_uri, &self.jwks) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err(IssuerMetadataError::InvalidMetadata {
                message: "metadata must include either jwks_uri or jwks".into(),
            }),
            (Some(_), Some(_)) => Err(IssuerMetadataError::InvalidMetadata {
                message: "metadata must not include both jwks_uri and jwks".into(),
            }),
        }
    }
}

/// Finds a key by `kid` in the resolved JWK Set.
pub fn key_by_id<'a>(jwks: &'a JwkSet, kid: &str) -> Option<&'a Jwk> {
    jwks.keys
        .iter()
        .find(|key| key.prm.kid.as_deref() == Some(kid))
}

/// Resolves JWT VC issuer signing JWK Set.
pub(super) async fn resolve(
    sd_jwt: &SdJwt<'_>,
    http_client: &ClientWithMiddleware,
) -> Result<JwkSet, IssuerMetadataError> {
    let issuer = sd_jwt
        .jwt()
        .claims()
        .rfc7519
        .iss
        .as_deref()
        .ok_or_else(|| IssuerMetadataError::InvalidIssuer {
            message: "issuer-signed JWT is missing iss".into(),
        })?;

    resolve_issuer(http_client, issuer).await
}

/// Resolves metadata for an issuer identifier.
async fn resolve_issuer(
    http_client: &ClientWithMiddleware,
    issuer: &str,
) -> Result<JwkSet, IssuerMetadataError> {
    let issuer_url = validate_issuer_url(issuer)?;
    let metadata_url = jwt_vc_issuer_metadata_url(&issuer_url);
    let metadata = fetch_metadata(http_client, &metadata_url).await?;
    metadata.validate_for_issuer(issuer)?;
    let jwks = resolve_jwks(http_client, metadata).await?;
    Ok(jwks)
}

async fn fetch_metadata(
    http_client: &ClientWithMiddleware,
    url: &Url,
) -> Result<IssuerMetadata, IssuerMetadataError> {
    let response = http_client
        .get(url.as_str())
        .send()
        .await
        .map_err(|source| IssuerMetadataError::Http {
            message: Some("failed to fetch JWT VC issuer metadata".into()),
            status: None,
            body: None,
            source: Some(Box::new(source)),
        })?;

    if response.status() != StatusCode::OK {
        return Err(http_error_response(
            response,
            "JWT VC issuer metadata endpoint returned an error",
        )
        .await);
    }

    response
        .json::<IssuerMetadata>()
        .await
        .map_err(|source| IssuerMetadataError::InvalidResponse {
            message: "failed to parse JWT VC issuer metadata".into(),
            source: Some(Box::new(source)),
        })
}

async fn resolve_jwks(
    http_client: &ClientWithMiddleware,
    metadata: IssuerMetadata,
) -> Result<JwkSet, IssuerMetadataError> {
    if let Some(jwks) = metadata.jwks {
        return Ok(jwks);
    }

    // Safety: metadata validation ensures jwks_uri or jwks is present
    let jwks_uri = metadata.jwks_uri.unwrap();

    let response = http_client
        .get(jwks_uri.as_str())
        .send()
        .await
        .map_err(|source| IssuerMetadataError::Http {
            message: Some("failed to fetch JWT VC issuer JWKS".into()),
            status: None,
            body: None,
            source: Some(Box::new(source)),
        })?;

    if response.status() != StatusCode::OK {
        return Err(
            http_error_response(response, "JWT VC issuer JWKS endpoint returned an error").await,
        );
    }

    response
        .json::<JwkSet>()
        .await
        .map_err(|source| IssuerMetadataError::InvalidResponse {
            message: "failed to parse JWT VC issuer JWKS".into(),
            source: Some(Box::new(source)),
        })
}

/// Builds the JWT VC Issuer Metadata well-known URL for an issuer.
///
/// The well-known suffix is inserted between the host component and the issuer
/// path component, after removing any terminating slash from that path.
fn jwt_vc_issuer_metadata_url(issuer: &Url) -> Url {
    let mut url = issuer.clone();
    let path = issuer.path().trim_end_matches('/');
    url.set_path(&format!("{JWT_VC_ISSUER_WELL_KNOWN}{path}"));
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn validate_issuer_url(issuer: &str) -> Result<Url, IssuerMetadataError> {
    let url = Url::parse(issuer).map_err(|source| IssuerMetadataError::InvalidIssuer {
        message: format!("issuer is not a valid URL: {source}").into(),
    })?;

    if url.host().is_none() || url.scheme() != "https" {
        return Err(IssuerMetadataError::InvalidIssuer {
            message: "issuer must include a host and use https scheme".into(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(IssuerMetadataError::InvalidIssuer {
            message: "issuer must not include query or fragment components".into(),
        });
    }
    Ok(url)
}

async fn http_error_response(
    response: reqwest::Response,
    message: &'static str,
) -> IssuerMetadataError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    IssuerMetadataError::Http {
        message: Some(message.into()),
        status: Some(status),
        body: Some(body),
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_jwks() -> serde_json::Value {
        json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
                    "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
                    "kid": "key-1"
                }
            ]
        })
    }

    #[test]
    fn builds_well_known_url_for_root_issuer() {
        let issuer = Url::parse("https://example.com").unwrap();

        assert_eq!(
            jwt_vc_issuer_metadata_url(&issuer).as_str(),
            "https://example.com/.well-known/jwt-vc-issuer"
        );
    }

    #[test]
    fn builds_well_known_url_for_path_issuer() {
        let issuer = Url::parse("https://example.com/tenant/1234/").unwrap();

        assert_eq!(
            jwt_vc_issuer_metadata_url(&issuer).as_str(),
            "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"
        );
    }

    #[test]
    fn validates_exactly_one_jwk_source() {
        let issuer = "https://example.com";
        let missing = IssuerMetadata {
            issuer: issuer.to_owned(),
            jwks_uri: None,
            jwks: None,
        };
        assert!(matches!(
            missing.validate_for_issuer(issuer),
            Err(IssuerMetadataError::InvalidMetadata { .. })
        ));

        let both = IssuerMetadata {
            issuer: issuer.to_owned(),
            jwks_uri: Some(Url::parse("https://example.com/jwks.json").unwrap()),
            jwks: Some(serde_json::from_value(test_jwks()).unwrap()),
        };
        assert!(matches!(
            both.validate_for_issuer(issuer),
            Err(IssuerMetadataError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn validates_metadata_issuer_matches_jwt_issuer() {
        let metadata = IssuerMetadata {
            issuer: "https://other.example.com".to_owned(),
            jwks_uri: None,
            jwks: Some(serde_json::from_value(test_jwks()).unwrap()),
        };

        assert!(matches!(
            metadata.validate_for_issuer("https://example.com"),
            Err(IssuerMetadataError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn validates_issuer_identifier_shape() {
        assert!(matches!(
            validate_issuer_url("http://example.com"),
            Err(IssuerMetadataError::InvalidIssuer { .. })
        ));
        assert!(matches!(
            validate_issuer_url("https://example.com?x=1"),
            Err(IssuerMetadataError::InvalidIssuer { .. })
        ));
    }

    #[tokio::test]
    async fn resolves_inline_jwks_metadata() {
        let mock_server = MockServer::start().await;
        let issuer = "https://issuer.example.com";
        let metadata = json!({
            "issuer": issuer,
            "jwks": test_jwks()
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwt-vc-issuer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&mock_server)
            .await;

        let metadata_url =
            Url::parse(&format!("{}/.well-known/jwt-vc-issuer", mock_server.uri())).unwrap();
        let metadata = fetch_metadata(
            &ClientBuilder::new(reqwest::Client::new()).build(),
            &metadata_url,
        )
        .await
        .unwrap();
        metadata.validate_for_issuer(issuer).unwrap();
        let jwks = resolve_jwks(
            &ClientBuilder::new(reqwest::Client::new()).build(),
            metadata.clone(),
        )
        .await
        .unwrap();

        assert_eq!(metadata.issuer, issuer);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys
                .iter()
                .find(|key| key.prm.kid.as_deref() == Some("key-1"))
                .and_then(|key| key.prm.kid.as_deref()),
            Some("key-1")
        );
    }

    #[tokio::test]
    async fn resolves_jwks_uri_metadata() {
        let mock_server = MockServer::start().await;
        let issuer = "https://issuer.example.com";
        let metadata = json!({
            "issuer": issuer,
            "jwks_uri": format!("{}/jwks.json", mock_server.uri())
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/jwt-vc-issuer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_jwks()))
            .mount(&mock_server)
            .await;

        let metadata_url =
            Url::parse(&format!("{}/.well-known/jwt-vc-issuer", mock_server.uri())).unwrap();
        let metadata = fetch_metadata(
            &ClientBuilder::new(reqwest::Client::new()).build(),
            &metadata_url,
        )
        .await
        .unwrap();
        metadata.validate_for_issuer(issuer).unwrap();
        let jwks = resolve_jwks(
            &ClientBuilder::new(reqwest::Client::new()).build(),
            metadata,
        )
        .await
        .unwrap();

        assert_eq!(jwks.keys.len(), 1);
    }
}
