//! Credential Offer resolution.
//!
//! Resolves credential offers from URI strings with caching and validation.

use std::time::Duration;

use crate::errors::Error;
use crate::http::HttpClient;
use crate::issuance::authz_server_metadata::AuthorizationServerMetadata;
use crate::issuance::credential_offer::{
    CredentialOffer, CredentialOfferSource, CredentialOfferUri,
};
use crate::issuance::issuer_metadata::CredentialIssuerMetadata;

use super::DEFAULT_CACHE_TTL_SECS;
use super::auth_server::AuthServerMetadataResolver;
use super::issuer::IssuerMetadataResolver;

/// Default maximum cache capacity.
pub const DEFAULT_MAX_CAPACITY: u64 = 1000;

/// The outcome of resolving a credential offer.
///
/// Contains the credential offer and all resolved metadata.
#[derive(Debug, Clone)]
pub struct ResolvedOffer {
    /// The credential offer.
    pub offer: CredentialOffer,
    /// The issuer metadata.
    pub issuer_metadata: CredentialIssuerMetadata,
    /// The authorization server metadata (if different from issuer).
    pub as_metadata: Option<AuthorizationServerMetadata>,
}

/// Resolves credential offers with associated metadata.
///
/// This resolver handles the complete flow of:
/// 1. Parsing the credential offer URI.
/// 2. Fetching the offer (if by reference).
/// 3. Resolving issuer metadata.
/// 4. Resolving authorization server metadata (if applicable).
///
/// # Example
///
/// ```ignore
/// use cloud_wallet_openid4vc::issuance::resolution::CredentialOfferResolver;
///
/// let resolver = CredentialOfferResolver::new()?;
/// let resolved = resolver.resolve("openid-credential-offer://?credential_offer=...").await?;
/// println!("Issuer: {}", resolved.offer.credential_issuer);
/// ```
#[derive(Clone)]
pub struct CredentialOfferResolver {
    http: HttpClient,
    issuer_resolver: IssuerMetadataResolver,
    as_resolver: AuthServerMetadataResolver,
}

impl CredentialOfferResolver {
    /// Creates a new resolver with default settings.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new() -> Result<Self, Error> {
        Self::with_config(
            Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            DEFAULT_MAX_CAPACITY,
        )
    }

    /// Creates a new resolver with custom cache settings.
    ///
    /// # Arguments
    ///
    /// * `cache_ttl` - Time-to-live for cached metadata.
    /// * `cache_capacity` - Maximum number of entries per cache.
    pub fn with_config(cache_ttl: Duration, cache_capacity: u64) -> Result<Self, Error> {
        let http = HttpClient::new()?;

        let issuer_resolver =
            IssuerMetadataResolver::with_config(http.clone(), cache_ttl, cache_capacity)?;

        let as_resolver =
            AuthServerMetadataResolver::with_config(http.clone(), cache_ttl, cache_capacity)?;

        Ok(Self {
            http,
            issuer_resolver,
            as_resolver,
        })
    }

    /// Creates a resolver from existing components.
    ///
    /// This is useful for dependency injection in tests or custom configurations.
    pub fn from_components(
        http: HttpClient,
        issuer_resolver: IssuerMetadataResolver,
        as_resolver: AuthServerMetadataResolver,
    ) -> Self {
        Self {
            http,
            issuer_resolver,
            as_resolver,
        }
    }

    /// Resolves a credential offer from a raw URI string.
    ///
    /// This method:
    /// 1. Parses the offer URI to extract the offer (by value or reference).
    /// 2. If by reference, fetches the offer via HTTP.
    /// 3. Resolves the issuer metadata.
    /// 4. Resolves the authorization server metadata if configured.
    ///
    /// # Arguments
    ///
    /// * `offer_uri` - The raw credential offer URI string. Can be:
    ///   - A full `openid-credential-offer://` URI
    ///   - A query string like `credential_offer=...`
    ///   - The value of the `credential_offer` or `credential_offer_uri` parameter
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The offer URI is malformed.
    /// - The offer fails validation.
    /// - Fetching the offer (by reference) fails.
    /// - Issuer metadata fetch fails.
    /// - Authorization server metadata fetch fails (if applicable).
    pub async fn resolve(&self, offer_uri: &str) -> Result<ResolvedOffer, Error> {
        let offer = self.resolve_offer(offer_uri).await?;
        let issuer_metadata = self.resolve_issuer_metadata(&offer).await?;
        let as_metadata = self.resolve_as_metadata(&offer, &issuer_metadata).await?;

        Ok(ResolvedOffer {
            offer,
            issuer_metadata,
            as_metadata,
        })
    }

    /// Resolves just the credential offer (without metadata).
    ///
    /// This is useful when you only need the offer itself.
    pub async fn resolve_offer(&self, offer_uri: &str) -> Result<CredentialOffer, Error> {
        let parsed = if offer_uri.contains("://") || offer_uri.starts_with("credential_offer") {
            CredentialOfferUri::from_offer_link(offer_uri)?
        } else {
            CredentialOfferUri::from_query(offer_uri)?
        };

        match parsed.source {
            CredentialOfferSource::ByValue(offer) => Ok(offer),
            CredentialOfferSource::ByReference(uri) => self.fetch_offer_by_reference(&uri).await,
        }
    }

    /// Fetches a credential offer by reference.
    async fn fetch_offer_by_reference(&self, uri: &str) -> Result<CredentialOffer, Error> {
        crate::issuance::credential_offer::resolve_by_reference(uri, &self.http.inner).await
    }

    /// Resolves issuer metadata for the offer.
    async fn resolve_issuer_metadata(
        &self,
        offer: &CredentialOffer,
    ) -> Result<CredentialIssuerMetadata, Error> {
        self.issuer_resolver.resolve(&offer.credential_issuer).await
    }

    /// Resolves authorization server metadata if applicable.
    ///
    /// Returns `None` if the issuer uses itself as the authorization server.
    async fn resolve_as_metadata(
        &self,
        offer: &CredentialOffer,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<Option<AuthorizationServerMetadata>, Error> {
        let as_url = self.determine_as_url(offer, issuer_metadata)?;

        match as_url {
            Some(url) => {
                let metadata = self.as_resolver.resolve(&url).await?;
                Ok(Some(metadata))
            }
            None => Ok(None),
        }
    }

    /// Determines the authorization server URL for the offer.
    ///
    /// Priority:
    /// 1. `authorization_server` in the grant (if present)
    /// 2. First entry in `authorization_servers` from issuer metadata
    /// 3. The issuer URL itself (returns `None` - no separate AS)
    fn determine_as_url(
        &self,
        offer: &CredentialOffer,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<Option<String>, Error> {
        if let Some(grants) = &offer.grants {
            if let Some(auth_code) = &grants.authorization_code {
                if let Some(as_url) = &auth_code.authorization_server {
                    return Ok(Some(as_url.clone()));
                }
            }
            if let Some(pre_auth) = &grants.pre_authorized_code {
                if let Some(as_url) = &pre_auth.authorization_server {
                    return Ok(Some(as_url.clone()));
                }
            }
        }

        if let Some(auth_servers) = &issuer_metadata.authorization_servers {
            if !auth_servers.is_empty() {
                let first = &auth_servers[0];
                return Ok(Some(first.to_string()));
            }
        }

        Ok(None)
    }

    /// Returns a reference to the issuer metadata resolver.
    pub fn issuer_resolver(&self) -> &IssuerMetadataResolver {
        &self.issuer_resolver
    }

    /// Returns a reference to the authorization server metadata resolver.
    pub fn as_resolver(&self) -> &AuthServerMetadataResolver {
        &self.as_resolver
    }

    /// Invalidates all cached metadata.
    pub async fn invalidate_all(&self) {
        self.issuer_resolver.invalidate_all().await;
        self.as_resolver.invalidate_all().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_creation_succeeds() {
        let resolver = CredentialOfferResolver::new();
        assert!(resolver.is_ok());
    }

    #[test]
    fn resolver_with_custom_config() {
        let resolver = CredentialOfferResolver::with_config(Duration::from_secs(60), 100);
        assert!(resolver.is_ok());
    }
}
