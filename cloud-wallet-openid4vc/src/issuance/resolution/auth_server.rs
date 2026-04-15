//! Authorization Server Metadata resolution.
//!
//! Fetches and caches OAuth 2.0 Authorization Server Metadata from well-known
//! endpoints as defined in [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414).

use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::errors::{Error, ErrorKind};
use crate::http::HttpClient;
use crate::issuance::authz_server_metadata::AuthorizationServerMetadata;

use super::cache::{DEFAULT_CACHE_TTL_SECS, MetadataCache, as_cache_key, create_cache};

/// Well-known path for OAuth 2.0 Authorization Server Metadata (RFC 8414).
pub const OAUTH_AS_WELL_KNOWN: &str = ".well-known/oauth-authorization-server";

/// Well-known path for OpenID Connect Discovery.
pub const OIDC_WELL_KNOWN: &str = ".well-known/openid-configuration";

/// Resolves Authorization Server Metadata with caching.
///
/// This resolver fetches the authorization server's metadata document from
/// well-known endpoints and caches it with a configurable TTL. It tries the
/// OAuth AS endpoint first, falling back to OIDC discovery if that fails.
///
/// # Endpoints Tried (in order)
///
/// 1. `/.well-known/oauth-authorization-server` (RFC 8414)
/// 2. `/.well-known/openid-configuration` (OIDC Discovery)
///
/// # Example
///
/// ```ignore
/// use cloud_wallet_openid4vc::issuance::resolution::AuthServerMetadataResolver;
///
/// let resolver = AuthServerMetadataResolver::new(http_client)?;
/// let metadata = resolver.resolve("https://auth.example.com").await?;
/// println!("Token endpoint: {:?}", metadata.token_endpoint);
/// ```
#[derive(Clone)]
pub struct AuthServerMetadataResolver {
    http: HttpClient,
    cache: Arc<MetadataCache<AuthorizationServerMetadata>>,
}

impl AuthServerMetadataResolver {
    /// Creates a new resolver with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(http: HttpClient) -> Result<Self, Error> {
        Self::with_config(http, Duration::from_secs(DEFAULT_CACHE_TTL_SECS), 1000)
    }

    /// Creates a new resolver with custom cache settings.
    ///
    /// # Arguments
    ///
    /// * `http` - HTTP client for fetching metadata.
    /// * `cache_ttl` - Time-to-live for cached metadata.
    /// * `cache_capacity` - Maximum number of entries in the cache.
    pub fn with_config(
        http: HttpClient,
        cache_ttl: Duration,
        cache_capacity: u64,
    ) -> Result<Self, Error> {
        let cache = Arc::new(create_cache(cache_ttl, cache_capacity));

        Ok(Self { http, cache })
    }

    /// Resolves the authorization server metadata for the given AS URL.
    ///
    /// This method:
    /// 1. Checks the cache for a valid entry.
    /// 2. On miss, tries `/.well-known/oauth-authorization-server`.
    /// 3. Falls back to `/.well-known/openid-configuration` if the first fails.
    /// 4. Validates the metadata.
    /// 5. Caches the result and returns it.
    ///
    /// # Errors
    ///
    /// Returns an error with [`ErrorKind::AuthServerMetadataFetchFailed`] if:
    /// - The AS URL is not a valid HTTPS URL.
    /// - Both well-known endpoints fail (network error, timeout, non-200 response).
    /// - The response body is not valid JSON.
    /// - The metadata fails validation.
    pub async fn resolve(&self, as_url: &str) -> Result<AuthorizationServerMetadata, Error> {
        let cache_key = as_cache_key(as_url);

        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let metadata = self.fetch(as_url).await?;
        self.cache.insert(cache_key, metadata.clone()).await;
        Ok(metadata)
    }

    /// Fetches AS metadata, trying both well-known paths.
    async fn fetch(&self, as_url: &str) -> Result<AuthorizationServerMetadata, Error> {
        let base_url = self.validate_as_url(as_url)?;

        let oauth_url = self.build_well_known_url(&base_url, OAUTH_AS_WELL_KNOWN)?;

        match self.try_fetch(&oauth_url, &base_url).await {
            Ok(metadata) => return Ok(metadata),
            Err(e) => {
                tracing::debug!("OAuth AS metadata fetch failed from {}: {}", oauth_url, e);
            }
        }

        let oidc_url = self.build_well_known_url(&base_url, OIDC_WELL_KNOWN)?;
        self.try_fetch(&oidc_url, &base_url).await
    }

    /// Attempts to fetch and validate metadata from a specific URL.
    async fn try_fetch(
        &self,
        well_known_url: &str,
        expected_issuer: &Url,
    ) -> Result<AuthorizationServerMetadata, Error> {
        let response = self
            .http
            .get_json::<AuthorizationServerMetadata>(well_known_url)
            .send()
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::HttpRequestFailed {
                    Error::new(ErrorKind::AuthServerMetadataFetchFailed, e)
                } else {
                    e
                }
            })?;

        let metadata = response.body;

        metadata.validate().map_err(|e| {
            Error::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                format!("metadata from {} failed validation: {}", well_known_url, e),
            )
        })?;

        if metadata.issuer.as_str() != expected_issuer.as_str() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                format!(
                    "issuer '{}' does not match requested URL '{}'",
                    metadata.issuer, expected_issuer
                ),
            ));
        }

        Ok(metadata)
    }

    /// Validates the authorization server URL.
    fn validate_as_url(&self, as_url: &str) -> Result<Url, Error> {
        let url = Url::parse(as_url).map_err(|e| {
            Error::message(
                ErrorKind::AuthServerMetadataFetchFailed,
                format!("invalid URL: {}", e),
            )
        })?;

        if url.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::AuthServerMetadataFetchFailed,
                format!("AS URL must use https scheme, got '{}'", url.scheme()),
            ));
        }

        Ok(url)
    }

    /// Builds a well-known URL for AS metadata.
    fn build_well_known_url(&self, base_url: &Url, path: &str) -> Result<String, Error> {
        let mut well_known = base_url.clone();

        let existing_path = well_known.path();
        let new_path = if existing_path.ends_with('/') {
            format!("{}{}", existing_path, path)
        } else {
            format!("{}/{}", existing_path, path)
        };

        well_known.set_path(&new_path);
        Ok(well_known.to_string())
    }

    /// Invalidates the cache entry for the given AS URL.
    pub async fn invalidate(&self, as_url: &str) {
        let cache_key = as_cache_key(as_url);
        self.cache.remove(&cache_key).await;
    }

    /// Invalidates all cache entries.
    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all().await;
    }

    /// Returns the number of cached entries.
    pub fn cache_size(&self) -> u64 {
        self.cache.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod builder_tests {
        use super::*;

        #[test]
        fn build_well_known_url_oauth() {
            let http = HttpClient::new().unwrap();
            let resolver = AuthServerMetadataResolver::new(http).unwrap();
            let base = Url::parse("https://auth.example.com").unwrap();

            let url = resolver
                .build_well_known_url(&base, OAUTH_AS_WELL_KNOWN)
                .unwrap();

            assert_eq!(
                url,
                "https://auth.example.com/.well-known/oauth-authorization-server"
            );
        }

        #[test]
        fn build_well_known_url_oidc() {
            let http = HttpClient::new().unwrap();
            let resolver = AuthServerMetadataResolver::new(http).unwrap();
            let base = Url::parse("https://auth.example.com").unwrap();

            let url = resolver
                .build_well_known_url(&base, OIDC_WELL_KNOWN)
                .unwrap();

            assert_eq!(
                url,
                "https://auth.example.com/.well-known/openid-configuration"
            );
        }

        #[test]
        fn build_well_known_url_preserves_path() {
            let http = HttpClient::new().unwrap();
            let resolver = AuthServerMetadataResolver::new(http).unwrap();
            let base = Url::parse("https://auth.example.com/tenant1").unwrap();

            let url = resolver
                .build_well_known_url(&base, OAUTH_AS_WELL_KNOWN)
                .unwrap();

            assert!(url.contains("/tenant1/"));
            assert!(url.ends_with(OAUTH_AS_WELL_KNOWN));
        }

        #[test]
        fn validate_as_url_accepts_https() {
            let http = HttpClient::new().unwrap();
            let resolver = AuthServerMetadataResolver::new(http).unwrap();

            let result = resolver.validate_as_url("https://auth.example.com");
            assert!(result.is_ok());
        }

        #[test]
        fn validate_as_url_rejects_http() {
            let http = HttpClient::new().unwrap();
            let resolver = AuthServerMetadataResolver::new(http).unwrap();

            let result = resolver.validate_as_url("http://auth.example.com");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::AuthServerMetadataFetchFailed);
        }
    }
}
