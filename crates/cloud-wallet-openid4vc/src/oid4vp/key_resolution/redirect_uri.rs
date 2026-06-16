//! Key resolution for the `redirect_uri:` client identifier prefix per OpenID4VP §5.9.3.

use cloud_wallet_crypto::jwk::{Jwk, JwkSet};
use jsonwebtoken::{DecodingKey, Header, jwk::Jwk as JwtJwk};
use reqwest::StatusCode;
use reqwest_middleware::ClientWithMiddleware;
use url::Url;

use crate::errors::{Error, ErrorKind};
use crate::oid4vp::client_id::{ClientIdPrefix, ParsedClientId};
use crate::oid4vp::key_resolution::error::RedirectUriKeyError;
use crate::oid4vp::metadata::verifier::VerifierMetadata;
use crate::oid4vp::request_object::VerifierKeyResolver;

const OAUTH_WELL_KNOWN: &str = "/.well-known/oauth-authorization-server";

pub struct RedirectUriKeyResolver {
    http_client: ClientWithMiddleware,
}

impl RedirectUriKeyResolver {
    pub fn new(http_client: ClientWithMiddleware) -> Self {
        Self { http_client }
    }

    async fn fetch_metadata(
        &self,
        redirect_uri: &Url,
    ) -> Result<VerifierMetadata, RedirectUriKeyError> {
        let metadata_url = build_metadata_url(redirect_uri)?;

        let response = self
            .http_client
            .get(metadata_url.as_str())
            .send()
            .await
            .map_err(|source| RedirectUriKeyError::MetadataFetchFailed {
                message: "failed to fetch verifier metadata".into(),
                status: None,
                body: None,
                source: Some(Box::new(source)),
            })?;

        if response.status() != StatusCode::OK {
            return Err(metadata_error_response(
                response,
                "verifier metadata endpoint returned error",
            )
            .await);
        }

        let metadata: VerifierMetadata = response.json().await.map_err(|source| {
            RedirectUriKeyError::InvalidMetadata(format!(
                "failed to parse verifier metadata: {source}"
            ))
        })?;

        Ok(metadata)
    }

    async fn resolve_jwks(
        &self,
        metadata: VerifierMetadata,
    ) -> Result<JwkSet, RedirectUriKeyError> {
        if let Some(jwks) = metadata.client_metadata.jwks {
            return Ok(jwks);
        }

        let jwks_uri = metadata.client_metadata.jwks_uri.ok_or_else(|| {
            RedirectUriKeyError::InvalidMetadata(
                "verifier metadata must include either jwks or jwks_uri".to_string(),
            )
        })?;

        self.fetch_jwks(&jwks_uri).await
    }

    async fn fetch_jwks(&self, jwks_uri: &Url) -> Result<JwkSet, RedirectUriKeyError> {
        let response = self
            .http_client
            .get(jwks_uri.as_str())
            .send()
            .await
            .map_err(|source| RedirectUriKeyError::JwksFetchFailed {
                message: "failed to fetch JWKS".into(),
                status: None,
                body: None,
                source: Some(Box::new(source)),
            })?;

        if response.status() != StatusCode::OK {
            return Err(jwks_error_response(response, "JWKS endpoint returned error").await);
        }

        let jwks = response.json::<JwkSet>().await.map_err(|source| {
            RedirectUriKeyError::JwksParseFailed(format!("failed to parse JWKS response: {source}"))
        })?;

        validate_jwks_key_ids(&jwks)?;

        Ok(jwks)
    }

    fn select_key<'a>(jwks: &'a JwkSet, header: &Header) -> Result<&'a Jwk, RedirectUriKeyError> {
        if jwks.keys.is_empty() {
            return Err(RedirectUriKeyError::EmptyJwks);
        }

        let kid = header
            .kid
            .as_ref()
            .ok_or(RedirectUriKeyError::MissingKeyId)?;

        jwks.keys
            .iter()
            .find(|key| key.prm.kid.as_deref() == Some(kid))
            .ok_or_else(|| RedirectUriKeyError::KeyNotFound(kid.clone()))
    }
}

#[async_trait::async_trait]
impl VerifierKeyResolver for RedirectUriKeyResolver {
    async fn resolve_key(
        &self,
        client_id: &ParsedClientId,
        header: &Header,
    ) -> crate::errors::Result<DecodingKey> {
        if client_id.prefix() != Some(ClientIdPrefix::RedirectUri) {
            return Err(Error::new(
                ErrorKind::InvalidPresentationRequest,
                RedirectUriKeyError::InvalidClientIdPrefix(format!("{:?}", client_id.prefix())),
            ));
        }

        let redirect_uri_str = client_id.value();
        let redirect_uri = Url::parse(redirect_uri_str).map_err(|e| {
            Error::new(
                ErrorKind::InvalidPresentationRequest,
                RedirectUriKeyError::InvalidRedirectUri(e.to_string()),
            )
        })?;

        let metadata = self
            .fetch_metadata(&redirect_uri)
            .await
            .map_err(|e| Error::new(ErrorKind::InvalidVerifierMetadata, e))?;

        let jwks = self
            .resolve_jwks(metadata)
            .await
            .map_err(|e| Error::new(ErrorKind::InvalidVerifierMetadata, e))?;

        let jwk = Self::select_key(&jwks, header)
            .map_err(|e| Error::new(ErrorKind::InvalidVerifierMetadata, e))?;

        jwk_to_decoding_key(jwk).map_err(|e| Error::new(ErrorKind::InvalidVerifierMetadata, e))
    }
}

fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, RedirectUriKeyError> {
    let jwt_jwk = serde_json::to_value(jwk)
        .and_then(serde_json::from_value::<JwtJwk>)
        .map_err(|e| {
            RedirectUriKeyError::KeyConversionFailed(format!("failed to serialize JWK: {e}"))
        })?;

    DecodingKey::from_jwk(&jwt_jwk).map_err(|e| {
        RedirectUriKeyError::KeyConversionFailed(format!(
            "failed to create DecodingKey from JWK: {e}"
        ))
    })
}

fn build_metadata_url(redirect_uri: &Url) -> Result<Url, RedirectUriKeyError> {
    let mut url = redirect_uri.clone();

    let path = url.path().trim_end_matches('/');
    url.set_path(&format!("{OAUTH_WELL_KNOWN}{path}"));
    url.set_query(None);
    url.set_fragment(None);

    Ok(url)
}

async fn metadata_error_response(
    response: reqwest::Response,
    message: &'static str,
) -> RedirectUriKeyError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    RedirectUriKeyError::MetadataFetchFailed {
        message: message.into(),
        status: Some(status),
        body: Some(body),
        source: None,
    }
}

async fn jwks_error_response(
    response: reqwest::Response,
    message: &'static str,
) -> RedirectUriKeyError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    RedirectUriKeyError::JwksFetchFailed {
        message: message.into(),
        status: Some(status),
        body: Some(body),
        source: None,
    }
}

fn validate_jwks_key_ids(jwks: &JwkSet) -> Result<(), RedirectUriKeyError> {
    for jwk in &jwks.keys {
        if jwk.prm.kid.as_deref().is_none_or(str::is_empty) {
            return Err(RedirectUriKeyError::MissingKeyId);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;
    use reqwest_middleware::ClientBuilder;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_jwks_with_kid(kid: &str) -> serde_json::Value {
        json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTTIQ4Ro7WZjfOAfiNONFWEldFflZGdS1bE4R_0A",
                "y": "bK7XsC9RTVaLo5IT7wW2gA-e6K-XkWyhKyCfLJ7L_Hs",
                "kid": kid,
                "alg": "ES256"
            }]
        })
    }

    fn valid_verifier_metadata_jwks(jwks: serde_json::Value) -> serde_json::Value {
        json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            },
            "jwks": jwks
        })
    }

    fn valid_verifier_metadata_jwks_uri(jwks_uri: &str) -> serde_json::Value {
        json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            },
            "jwks_uri": jwks_uri
        })
    }

    fn create_test_resolver() -> RedirectUriKeyResolver {
        RedirectUriKeyResolver::new(ClientBuilder::new(reqwest::Client::new()).build())
    }

    #[test]
    fn selects_key_by_kid() {
        let jwks: JwkSet = serde_json::from_value(test_jwks_with_kid("test-key")).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-key".to_string());

        let key = RedirectUriKeyResolver::select_key(&jwks, &header).unwrap();
        assert_eq!(key.prm.kid.as_deref(), Some("test-key"));
    }

    #[test]
    fn rejects_empty_jwks() {
        let jwks: JwkSet = serde_json::from_value(json!({"keys": []})).unwrap();
        let header = Header::new(Algorithm::ES256);

        let result = RedirectUriKeyResolver::select_key(&jwks, &header);
        assert!(matches!(
            result.unwrap_err(),
            RedirectUriKeyError::EmptyJwks
        ));
    }

    #[test]
    fn rejects_multi_key_jwks_without_kid() {
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "MKBCTTIQ4Ro7WZjfOAfiNONFWEldFflZGdS1bE4R_0A",
                    "y": "bK7XsC9RTVaLo5IT7wW2gA-e6K-XkWyhKyCfLJ7L_Hs",
                    "kid": "key-1"
                },
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "weNJy2Hsc8l9SrgL-BslWqDg_tOpFCZeuS8YTTRt5Ds",
                    "y": "auxfJJofHF_trUBo0QnI2TvC8icPqL1FQz2W779v1_I",
                    "kid": "key-2"
                }
            ]
        }))
        .unwrap();
        let header = Header::new(Algorithm::ES256);

        let result = RedirectUriKeyResolver::select_key(&jwks, &header);
        assert!(matches!(
            result.unwrap_err(),
            RedirectUriKeyError::MissingKeyId
        ));
    }

    #[test]
    fn rejects_single_key_jwks_without_kid_in_header() {
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTTIQ4Ro7WZjfOAfiNONFWEldFflZGdS1bE4R_0A",
                "y": "bK7XsC9RTVaLo5IT7wW2gA-e6K-XkWyhKyCfLJ7L_Hs",
                "kid": "only-key"
            }]
        }))
        .unwrap();
        let header = Header::new(Algorithm::ES256);

        let result = RedirectUriKeyResolver::select_key(&jwks, &header);
        assert!(matches!(
            result.unwrap_err(),
            RedirectUriKeyError::MissingKeyId
        ));
    }

    #[tokio::test]
    async fn resolves_key_from_inline_jwks() {
        let mock_server = MockServer::start().await;
        let redirect_uri = format!("{}/callback", mock_server.uri());
        let metadata = valid_verifier_metadata_jwks(test_jwks_with_kid("test-key"));

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/callback"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&mock_server)
            .await;

        let resolver = create_test_resolver();
        let client_id = ParsedClientId::parse(format!("redirect_uri:{redirect_uri}")).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-key".to_string());

        assert!(resolver.resolve_key(&client_id, &header).await.is_ok());
    }

    #[tokio::test]
    async fn resolves_key_from_jwks_uri() {
        let mock_server = MockServer::start().await;
        let redirect_uri = format!("{}/callback", mock_server.uri());
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/callback"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(valid_verifier_metadata_jwks_uri(&jwks_uri)),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(test_jwks_with_kid("remote-key")),
            )
            .mount(&mock_server)
            .await;

        let resolver = create_test_resolver();
        let client_id = ParsedClientId::parse(format!("redirect_uri:{redirect_uri}")).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("remote-key".to_string());

        assert!(resolver.resolve_key(&client_id, &header).await.is_ok());
    }

    #[tokio::test]
    async fn rejects_wrong_client_id_prefix() {
        let resolver = create_test_resolver();
        let client_id = ParsedClientId::parse("x509_san_dns:verifier.example.com").unwrap();
        let header = Header::new(Algorithm::ES256);

        assert!(resolver.resolve_key(&client_id, &header).await.is_err());
    }

    #[tokio::test]
    async fn handles_metadata_error() {
        let mock_server = MockServer::start().await;
        let redirect_uri = format!("{}/callback", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/callback"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let resolver = create_test_resolver();
        let client_id = ParsedClientId::parse(format!("redirect_uri:{redirect_uri}")).unwrap();
        let header = Header::new(Algorithm::ES256);

        assert!(resolver.resolve_key(&client_id, &header).await.is_err());
    }

    #[tokio::test]
    async fn rejects_jwks_uri_without_kid() {
        let mock_server = MockServer::start().await;
        let redirect_uri = format!("{}/callback", mock_server.uri());
        let jwks_uri = format!("{}/jwks.json", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/callback"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(valid_verifier_metadata_jwks_uri(&jwks_uri)),
            )
            .mount(&mock_server)
            .await;

        let jwks_without_kid = json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": "MKBCTTIQ4Ro7WZjfOAfiNONFWEldFflZGdS1bE4R_0A",
                "y": "bK7XsC9RTVaLo5IT7wW2gA-e6K-XkWyhKyCfLJ7L_Hs",
                "alg": "ES256"
            }]
        });

        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_without_kid))
            .mount(&mock_server)
            .await;

        let resolver = create_test_resolver();
        let client_id = ParsedClientId::parse(format!("redirect_uri:{redirect_uri}")).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("any-key".to_string());

        let result = resolver.resolve_key(&client_id, &header).await;
        assert!(result.is_err());
    }

    #[test]
    fn build_metadata_url_basic() {
        let redirect_uri = Url::parse("https://example.com/callback").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server/callback"
        );
    }

    #[test]
    fn build_metadata_url_with_path() {
        let redirect_uri = Url::parse("https://example.com/app/callback").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server/app/callback"
        );
    }

    #[test]
    fn build_metadata_url_root_path() {
        let redirect_uri = Url::parse("https://example.com/").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn build_metadata_url_strips_trailing_slash() {
        let redirect_uri = Url::parse("https://example.com/callback/").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server/callback"
        );
    }

    #[test]
    fn build_metadata_url_removes_query() {
        let redirect_uri = Url::parse("https://example.com/callback?state=abc&code=123").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server/callback"
        );
    }

    #[test]
    fn build_metadata_url_removes_fragment() {
        let redirect_uri = Url::parse("https://example.com/callback#section").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com/.well-known/oauth-authorization-server/callback"
        );
    }

    #[test]
    fn build_metadata_url_complex() {
        let redirect_uri =
            Url::parse("https://example.com:8080/path/to/callback?foo=bar#anchor").unwrap();
        let metadata_url = build_metadata_url(&redirect_uri).unwrap();
        assert_eq!(
            metadata_url.as_str(),
            "https://example.com:8080/.well-known/oauth-authorization-server/path/to/callback"
        );
    }
}
