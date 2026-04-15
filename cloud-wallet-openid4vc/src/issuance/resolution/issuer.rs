//! Issuer Metadata resolution.
//!
//! Fetches and caches Credential Issuer Metadata from the well-known endpoint
//! as defined in [OpenID4VCI §11.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata).

use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::errors::{Error, ErrorKind};
use crate::http::HttpClient;
use crate::issuance::issuer_metadata::CredentialIssuerMetadata;

use super::cache::{DEFAULT_CACHE_TTL_SECS, MetadataCache, create_cache, issuer_cache_key};

/// Well-known path for Credential Issuer Metadata.
pub const CREDENTIAL_ISSUER_WELL_KNOWN: &str = ".well-known/openid-credential-issuer";

/// Resolves Credential Issuer Metadata with caching.
///
/// This resolver fetches the issuer's metadata document from
/// `/.well-known/openid-credential-issuer` and caches it with a configurable TTL.
/// On cache miss, it performs an HTTP GET request; on failure, it returns an error
/// without serving stale data.
///
/// # Example
///
/// ```ignore
/// use cloud_wallet_openid4vc::issuance::resolution::IssuerMetadataResolver;
///
/// let resolver = IssuerMetadataResolver::new(http_client)?;
/// let metadata = resolver.resolve("https://issuer.example.com").await?;
/// println!("Issuer: {}", metadata.credential_issuer);
/// ```
#[derive(Clone)]
pub struct IssuerMetadataResolver {
    http: HttpClient,
    cache: Arc<MetadataCache<CredentialIssuerMetadata>>,
}

impl IssuerMetadataResolver {
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

    /// Resolves the issuer metadata for the given issuer URL.
    ///
    /// This method:
    /// 1. Checks the cache for a valid entry.
    /// 2. On miss, fetches from `/.well-known/openid-credential-issuer`.
    /// 3. Validates the metadata.
    /// 4. Caches the result and returns it.
    ///
    /// # Errors
    ///
    /// Returns an error with [`ErrorKind::IssuerMetadataFetchFailed`] if:
    /// - The issuer URL is not a valid HTTPS URL.
    /// - The HTTP request fails (network error, timeout, non-200 response).
    /// - The response body is not valid JSON.
    /// - The metadata fails validation.
    pub async fn resolve(&self, issuer_url: &str) -> Result<CredentialIssuerMetadata, Error> {
        let cache_key = issuer_cache_key(issuer_url);

        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let metadata = self.fetch(issuer_url).await?;
        self.cache.insert(cache_key, metadata.clone()).await;
        Ok(metadata)
    }

    /// Fetches issuer metadata from the well-known endpoint.
    async fn fetch(&self, issuer_url: &str) -> Result<CredentialIssuerMetadata, Error> {
        let base_url = self.validate_issuer_url(issuer_url)?;
        let well_known_url = self.build_well_known_url(&base_url)?;

        let response = self
            .http
            .get_json::<CredentialIssuerMetadata>(&well_known_url)
            .send()
            .await
            .map_err(|e| {
                if e.kind() == ErrorKind::HttpRequestFailed {
                    Error::new(ErrorKind::IssuerMetadataFetchFailed, e)
                } else {
                    e
                }
            })?;

        let metadata = response.body;

        metadata.validate().map_err(|e| {
            Error::message(
                ErrorKind::InvalidIssuerMetadata,
                format!("metadata from {} failed validation: {}", well_known_url, e),
            )
        })?;

        if metadata.credential_issuer.as_str() != base_url.as_str() {
            return Err(Error::message(
                ErrorKind::InvalidIssuerMetadata,
                format!(
                    "credential_issuer '{}' does not match requested URL '{}'",
                    metadata.credential_issuer, base_url
                ),
            ));
        }

        Ok(metadata)
    }

    /// Validates the issuer URL.
    fn validate_issuer_url(&self, issuer_url: &str) -> Result<Url, Error> {
        let url = Url::parse(issuer_url).map_err(|e| {
            Error::message(
                ErrorKind::IssuerMetadataFetchFailed,
                format!("invalid URL: {}", e),
            )
        })?;

        if url.scheme() != "https" {
            return Err(Error::message(
                ErrorKind::IssuerMetadataFetchFailed,
                format!("issuer URL must use https scheme, got '{}'", url.scheme()),
            ));
        }

        Ok(url)
    }

    /// Builds the well-known URL for issuer metadata.
    fn build_well_known_url(&self, base_url: &Url) -> Result<String, Error> {
        let mut well_known = base_url.clone();

        let path = well_known.path();
        let new_path = if path.ends_with('/') {
            format!("{}{}", path, CREDENTIAL_ISSUER_WELL_KNOWN)
        } else {
            format!("{}/{}", path, CREDENTIAL_ISSUER_WELL_KNOWN)
        };

        well_known.set_path(&new_path);
        Ok(well_known.to_string())
    }

    /// Invalidates the cache entry for the given issuer URL.
    pub async fn invalidate(&self, issuer_url: &str) {
        let cache_key = issuer_cache_key(issuer_url);
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
        fn build_well_known_url_adds_path() {
            let http = HttpClient::new().unwrap();
            let resolver = IssuerMetadataResolver::new(http).unwrap();
            let base = Url::parse("https://issuer.example.com").unwrap();

            let url = resolver.build_well_known_url(&base).unwrap();

            assert!(url.ends_with(CREDENTIAL_ISSUER_WELL_KNOWN));
        }

        #[test]
        fn build_well_known_url_preserves_path() {
            let http = HttpClient::new().unwrap();
            let resolver = IssuerMetadataResolver::new(http).unwrap();
            let base = Url::parse("https://issuer.example.com/tenant1").unwrap();

            let url = resolver.build_well_known_url(&base).unwrap();

            assert!(url.contains("/tenant1/"));
            assert!(url.ends_with(CREDENTIAL_ISSUER_WELL_KNOWN));
        }

        #[test]
        fn validate_issuer_url_accepts_https() {
            let http = HttpClient::new().unwrap();
            let resolver = IssuerMetadataResolver::new(http).unwrap();

            let result = resolver.validate_issuer_url("https://issuer.example.com");
            assert!(result.is_ok());
        }

        #[test]
        fn validate_issuer_url_rejects_http() {
            let http = HttpClient::new().unwrap();
            let resolver = IssuerMetadataResolver::new(http).unwrap();

            let result = resolver.validate_issuer_url("http://issuer.example.com");
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::IssuerMetadataFetchFailed);
        }

        #[test]
        fn validate_issuer_url_rejects_invalid_url() {
            let http = HttpClient::new().unwrap();
            let resolver = IssuerMetadataResolver::new(http).unwrap();

            let result = resolver.validate_issuer_url("not a valid url");
            assert!(result.is_err());
        }
    }
}
