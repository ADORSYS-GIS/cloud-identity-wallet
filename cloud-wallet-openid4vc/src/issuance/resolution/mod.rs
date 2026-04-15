//! Metadata resolution for OpenID4VCI credential issuance.
//!
//! This module provides resolvers for fetching and caching metadata documents
//! required during the credential issuance flow:
//!
//! - [`CredentialOfferResolver`] - Resolves credential offers from URI strings
//! - [`IssuerMetadataResolver`] - Fetches Credential Issuer Metadata
//! - [`AuthServerMetadataResolver`] - Fetches Authorization Server Metadata
//!
//! # Architecture Overview
//!
//! The resolution system implements the metadata resolution requirements from
//! [OpenID4VCI Issue #143](https://github.com/ADORSYS-GIS/cloud-identity-wallet/issues/143).
//!
//! ## Resolution Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    POST /issuance/start (future)                    │
//! └─────────────────────────────────────────────────────────────────────┘
//!                                   │
//!                                   ▼
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                  CredentialOfferResolver::resolve()                 │
//! │                                                                     │
//! │  1. Parse offer URI                                                 │
//! │     ├── By value: Parse JSON directly (no HTTP)                    │
//! │     └── By reference: HTTP GET → parse JSON                        │
//! │                                                                     │
//! │  2. IssuerMetadataResolver::resolve()                               │
//! │     ├── Cache hit? → return cached                                  │
//! │     └── Cache miss: HTTP GET /.well-known/openid-credential-issuer │
//! │                                                                     │
//! │  3. AuthServerMetadataResolver::resolve() (if applicable)           │
//! │     ├── Cache hit? → return cached                                  │
//! │     └── Cache miss: Try /.well-known/oauth-authorization-server    │
//! │                    ↓ fallback: /.well-known/openid-configuration   │
//! └─────────────────────────────────────────────────────────────────────┘
//!                                   │
//!                                   ▼
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        ResolvedOffer                                │
//! │  - offer: CredentialOffer                                          │
//! │  - issuer_metadata: CredentialIssuerMetadata                       │
//! │  - as_metadata: Option<AuthorizationServerMetadata>                │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Caching Strategy
//!
//! All metadata is cached using [`cloud_wallet_kms::cache::Cache`] (moka-based)
//! with configurable TTL. Key design decisions:
//!
//! - **Cache keys**: SHA-256 hash of the metadata URL, prefixed by type
//!   - Issuer: `issuer:{sha256(url)}`
//!   - Auth Server: `as:{sha256(url)}`
//! - **TTL**: Configurable via `METADATA_CACHE_TTL_SECONDS` (default: 5 min)
//! - **No stale data**: On fetch failure, return error instead of serving expired
//! - **Coalescing**: Multiple concurrent requests for same key share one fetch
//!
//! ## Error Handling
//!
//! | Scenario | Error Kind | HTTP Status |
//! |----------|------------|-------------|
//! | Unreachable issuer metadata endpoint | `IssuerMetadataFetchFailed` | 502 |
//! | Unreachable AS metadata endpoint | `AuthServerMetadataFetchFailed` | 502 |
//! | Invalid metadata | `InvalidIssuerMetadata` / `InvalidAuthorizationServerMetadata` | 400 |
//! | Invalid offer | `InvalidCredentialOffer` | 400 |
//!
//! ## Module Structure
//!
//! ```text
//! issuance/resolution/
//! ├── mod.rs           # Module documentation and re-exports
//! ├── cache.rs         # Cache key generation and utilities
//! ├── offer.rs         # CredentialOfferResolver and ResolvedOffer
//! ├── issuer.rs        # IssuerMetadataResolver
//! └── auth_server.rs   # AuthServerMetadataResolver
//! ```
//!
//! ## Configuration
//!
//! Metadata resolution is configured via environment variables:
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `APP_METADATA__CACHE_TTL_SECS` | 300 | Cache TTL in seconds |
//! | `APP_METADATA__CACHE_MAX_ENTRIES` | 1000 | Max entries per cache |
//! | `APP_METADATA__HTTP_TIMEOUT_SECS` | 10 | HTTP request timeout |
//!
//! ## Usage Example
//!
//! ```ignore
//! use cloud_wallet_openid4vc::issuance::resolution::{
//!     CredentialOfferResolver, ResolvedOffer
//! };
//!
//! async fn handle_issuance_start(offer_uri: &str) -> Result<ResolvedOffer, Error> {
//!     let resolver = CredentialOfferResolver::new()?;
//!     let resolved = resolver.resolve(offer_uri).await?;
//!
//!     // Access resolved data
//!     println!("Issuer: {}", resolved.offer.credential_issuer);
//!     println!("Credentials: {:?}", resolved.offer.credential_configuration_ids);
//!     
//!     // Check for external authorization server
//!     if let Some(as_meta) = resolved.as_metadata {
//!         println!("Token endpoint: {:?}", as_meta.token_endpoint);
//!     }
//!     
//!     Ok(resolved)
//! }
//! ```
//!
//! ## Acceptance Criteria (from Issue #143)
//!
//! - [x] Inline offer JSON is parsed without an HTTP call
//! - [x] `credential_offer_uri` triggers exactly one HTTP GET
//! - [x] Issuer metadata is fetched and cached
//! - [x] Second call within TTL hits the cache
//! - [x] Unreachable issuer metadata endpoint returns `IssuerMetadataFetchFailed`
//! - [x] Unreachable AS metadata endpoint returns `AuthServerMetadataFetchFailed`

pub mod auth_server;
pub mod cache;
pub mod issuer;
pub mod offer;

pub use auth_server::{
    AuthServerMetadataResolver, OAUTH_AS_WELL_KNOWN, OIDC_WELL_KNOWN,
};
pub use cache::{
    as_cache_key, create_cache, issuer_cache_key, url_hash, MetadataCache,
    DEFAULT_CACHE_TTL_SECS, DEFAULT_MAX_CAPACITY,
};
pub use issuer::{IssuerMetadataResolver, CREDENTIAL_ISSUER_WELL_KNOWN};
pub use offer::{CredentialOfferResolver, ResolvedOffer};
