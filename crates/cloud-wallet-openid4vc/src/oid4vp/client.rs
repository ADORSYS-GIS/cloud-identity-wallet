//! OID4VP Wallet-Side Orchestrator Client.
//!
//! This module provides the top-level [`Oid4vpClient`] that orchestrates the
//! full OpenID4VP presentation flow by composing existing building blocks
//!
//! # Presentation Format Handling
//!
//! The client is **format-agnostic**. Format-specific presentation creation
//! (e.g., SD-JWT with Key Binding) is the caller's responsibility

mod error;
#[cfg(test)]
mod tests;

pub use error::Error;

use reqwest_middleware::ClientWithMiddleware;
use serde::Deserialize;
use url::Url;

use crate::oid4vp::authorization::request_uri::{RequestUriResult, resolve_request_uri};
use crate::oid4vp::authorization::{
    AuthorizationRequest, AuthorizationResponse, DirectPostResponse, RequestUriMethod, ResponseMode,
};
use crate::oid4vp::client_id::{ClientIdPrefix, ParsedClientId};
use crate::oid4vp::dcql::{CredentialQuery, DcqlQuery};
use crate::oid4vp::error::{AuthorizationErrorCode, RequestObjectError, RequestUriError};
use crate::oid4vp::metadata::verifier::VerifierMetadata;
use crate::oid4vp::metadata::wallet::WalletPresentationMetadata;
use crate::oid4vp::presentation::{PresentationBuilder, SelectedCredential};
use crate::oid4vp::request_object::{DiscoveryMode, RequestObject, VerifierKeyResolver};
use crate::oid4vp::response_mode::send_direct_post;
use crate::oid4vp::selection::{CredentialView, SelectionResult, match_dcql_query};
use crate::oid4vp::transaction_data::TransactionData;

/// Configuration for the [`Oid4vpClient`].
#[derive(Clone)]
pub struct Oid4vpConfig {
    /// HTTP client with middleware (redirect disabled, timeouts, etc.).
    pub http_client: ClientWithMiddleware,
    /// Static vs Dynamic discovery (controls `aud` validation in Request Object).
    pub discovery_mode: DiscoveryMode,
    /// Optional wallet metadata sent in POST request_uri resolution.
    pub wallet_metadata: Option<WalletPresentationMetadata>,
}

impl std::fmt::Debug for Oid4vpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oid4vpConfig")
            .field("discovery_mode", &self.discovery_mode)
            .field("wallet_metadata", &self.wallet_metadata)
            .finish_non_exhaustive()
    }
}

/// Resolves Request Objects referenced by `request_uri`.
///
/// Handlers can implement this trait to inject policy, caching, wallet nonce
/// generation, or mocked transport. The default [`HttpRequestUriResolver`]
/// delegates to the crate's spec-aware HTTP helpers.
#[async_trait::async_trait]
pub trait RequestUriResolver: Send + Sync {
    async fn resolve(
        &self,
        http_client: &ClientWithMiddleware,
        uri: &Url,
        method: Option<RequestUriMethod>,
        wallet_metadata: Option<&WalletPresentationMetadata>,
    ) -> Result<RequestUriResult, RequestUriError>;
}

/// Default HTTP-backed [`RequestUriResolver`].
///
/// Note: passes `None` for `wallet_nonce`. Callers requiring wallet nonce
/// binding should provide a custom [`RequestUriResolver`] implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct HttpRequestUriResolver;

#[async_trait::async_trait]
impl RequestUriResolver for HttpRequestUriResolver {
    async fn resolve(
        &self,
        http_client: &ClientWithMiddleware,
        uri: &Url,
        method: Option<RequestUriMethod>,
        wallet_metadata: Option<&WalletPresentationMetadata>,
    ) -> Result<RequestUriResult, RequestUriError> {
        resolve_request_uri(http_client, uri, method, wallet_metadata, None).await
    }
}

/// Resolves verifier trust material for a parsed `client_id`.
///
/// This trait extends [`VerifierKeyResolver`]: the same caller
/// that knows how to route `redirect_uri`, `x509_san_dns`, `x509_hash`,
/// `decentralized_identifier`, `openid_federation`, `verifier_attestation`, or
/// pre-registered clients can both provide Request Object verification keys and
/// return display/policy metadata.
#[async_trait::async_trait]
pub trait VerifierResolver: VerifierKeyResolver {
    async fn resolve_metadata(
        &self,
        _client_id: &ParsedClientId,
        _request: &AuthorizationRequest,
    ) -> Result<Option<VerifierMetadata>, Error> {
        Ok(None)
    }
}

/// Sends a completed Authorization Response to the Verifier.
///
/// Callers can replace this to add JARM (`direct_post.jwt`) encryption, DC API
/// delivery, audit hooks, or test doubles without changing VP-token creation.
#[async_trait::async_trait]
pub trait AuthzResponseSender: Send + Sync {
    async fn send(
        &self,
        http_client: &ClientWithMiddleware,
        context: &PresentationContext,
        response: &AuthorizationResponse,
    ) -> Result<DirectPostResponse, Error>;
}

/// Default sender for plain `direct_post`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectPostResponseSender;

#[async_trait::async_trait]
impl AuthzResponseSender for DirectPostResponseSender {
    async fn send(
        &self,
        http_client: &ClientWithMiddleware,
        context: &PresentationContext,
        response: &AuthorizationResponse,
    ) -> Result<DirectPostResponse, Error> {
        match context.response_mode {
            ResponseMode::DirectPost => {
                let response_uri = context.require_response_uri()?;
                // response_uri is used as both the endpoint and the expected URI
                // because both derive from the validated AuthorizationRequest.
                send_direct_post(http_client, response_uri, response_uri, response)
                    .await
                    .map_err(Into::into)
            }
            ResponseMode::DirectPostJwt => Err(Error::UnsupportedResponseMode(
                "direct_post.jwt requires an encrypted response sender",
            )),
            ResponseMode::DcApi | ResponseMode::DcApiJwt => Err(Error::UnsupportedResponseMode(
                "dc_api response modes are handled by the Digital Credentials API surface",
            )),
            ResponseMode::Other(_) => {
                Err(Error::UnsupportedResponseMode("unsupported response mode"))
            }
        }
    }
}

/// Validated intermediate state produced by [`Oid4vpClient::process_authz_request`].
#[derive(Debug)]
pub struct PresentationContext {
    /// The validated authorization request.
    pub request: AuthorizationRequest,
    /// Verifier metadata resolved by the handler from the client_id scheme.
    pub verifier_metadata: Option<VerifierMetadata>,
    /// Parsed client identifier with scheme information.
    pub client_id: ParsedClientId,
    /// Request nonce (used in KB-JWT and response binding).
    pub nonce: String,
    /// Optional state echoed in the response.
    pub state: Option<String>,
    /// Verifier's response_uri for direct_post delivery.
    pub response_uri: Option<Url>,
    /// Response mode from the request.
    pub response_mode: ResponseMode,
    /// Decoded DCQL query from the authorization request.
    pub dcql_query: DcqlQuery,
    /// Decoded transaction data.
    ///
    /// Decoded from the base64url-encoded `transaction_data` entries in the
    /// authorization request. Empty when no transaction data is present.
    pub transaction_data: Vec<TransactionData<'static>>,
}

impl PresentationContext {
    /// Returns the credential queries from the DCQL query.
    pub fn credential_queries(&self) -> &[CredentialQuery] {
        &self.dcql_query.credentials
    }

    /// Returns `true` if transaction data is present and requires user acknowledgment.
    pub fn has_transaction_data(&self) -> bool {
        !self.transaction_data.is_empty()
    }

    /// Returns the response_uri, or `Err(Oid4vpError::NoResponseUri)` if absent.
    fn require_response_uri(&self) -> Result<&Url, Error> {
        self.response_uri.as_ref().ok_or(Error::NoResponseUri)
    }
}

/// Unvalidated envelope extracted from the raw authorization request.
///
/// Only `client_id` and the location of the Request Object (`request_uri` / `request`)
/// are needed at this stage. Full deserialization and validation happen after the
/// Request Object is resolved and decoded.
#[derive(Debug, Deserialize)]
struct AuthorizationRequestEnvelope {
    client_id: String,
    request_uri: Option<Url>,
    request_uri_method: Option<RequestUriMethod>,
    request: Option<String>,
}

/// OID4VP Wallet-Side Orchestrator Client.
///
/// Composes existing building blocks into a cohesive presentation flow.
pub struct Oid4vpClient {
    config: Oid4vpConfig,
}

impl Oid4vpClient {
    /// Creates a new `Oid4vpClient` with the given configuration.
    pub fn new(config: Oid4vpConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the client configuration.
    pub fn config(&self) -> &Oid4vpConfig {
        &self.config
    }

    /// Processes a raw OID4VP authorization request into a validated [`PresentationContext`].
    ///
    /// # Pipeline
    ///
    /// 1. Parse `raw_request` as JSON → [`AuthorizationRequest`]
    /// 2. Validate the parsed request
    /// 3. If `request_uri` is present: resolve via GET/POST, then decode+validate
    /// 4. If `request` (inline JWT) is present: decode+validate directly
    /// 5. Otherwise: use the parsed request directly (unsigned — only valid for
    ///    `redirect_uri:` prefix or pre-registered clients per OpenID4VP §5.9)
    /// 6. Parse `client_id` via [`ParsedClientId::parse`]
    /// 7. Decode `transaction_data` if present
    /// 8. Validate `dcql_query` is present (DCQL-only)
    pub async fn process_authz_request(
        &self,
        raw_request: &str,
        key_resolver: &dyn VerifierKeyResolver,
    ) -> Result<PresentationContext, Error> {
        self.process_authz_request_full(raw_request, key_resolver, None, &HttpRequestUriResolver)
            .await
    }

    /// Processes a raw request using caller-provided verifier and request URI resolvers.
    pub async fn process_authz_request_with_resolver(
        &self,
        raw_request: &str,
        verifier_resolver: &dyn VerifierResolver,
    ) -> Result<PresentationContext, Error> {
        self.process_authz_request_full(
            raw_request,
            verifier_resolver,
            Some(verifier_resolver),
            &HttpRequestUriResolver,
        )
        .await
    }

    /// Processes a raw request using fully injected handler components.
    pub async fn process_authz_request_full(
        &self,
        raw_request: &str,
        key_resolver: &dyn VerifierKeyResolver,
        verifier_resolver: Option<&dyn VerifierResolver>,
        request_uri_resolver: &dyn RequestUriResolver,
    ) -> Result<PresentationContext, Error> {
        let request = self
            .parse_and_resolve_authorization_request(
                raw_request,
                key_resolver,
                request_uri_resolver,
            )
            .await?;

        let client_id = ParsedClientId::parse(&request.oauth.client_id)?;
        let verifier_metadata = match verifier_resolver {
            Some(resolver) => resolver.resolve_metadata(&client_id, &request).await?,
            None => None,
        };
        let transaction_data = self.decode_transaction_data(&request)?;
        let dcql_query = request.dcql_query.clone().ok_or(Error::NoDcqlQuery)?;

        Ok(PresentationContext {
            nonce: request.nonce.clone(),
            state: request.oauth.state.clone(),
            response_uri: request.response_uri.clone(),
            response_mode: request.response_mode.clone(),
            dcql_query,
            transaction_data,
            verifier_metadata,
            client_id,
            request,
        })
    }

    /// Matches the wallet's credentials against the DCQL query in the context.
    pub fn match_credentials(
        &self,
        ctx: &PresentationContext,
        credentials: &[CredentialView],
    ) -> SelectionResult {
        match_dcql_query(&ctx.dcql_query, credentials)
    }

    /// Builds and sends a VP Token response to the Verifier.
    pub async fn create_response(
        &self,
        ctx: &PresentationContext,
        selected: Vec<SelectedCredential>,
    ) -> Result<DirectPostResponse, Error> {
        self.create_response_with_sender(ctx, selected, &DirectPostResponseSender)
            .await
    }

    /// Builds and sends a VP Token response using a caller-provided sender.
    pub async fn create_response_with_sender(
        &self,
        ctx: &PresentationContext,
        selected: Vec<SelectedCredential>,
        sender: &dyn AuthzResponseSender,
    ) -> Result<DirectPostResponse, Error> {
        let vp_token = PresentationBuilder::new()
            .add_credentials(selected)
            .build_vp_token(ctx.credential_queries())?;

        let mut response = AuthorizationResponse::new(vp_token);
        if let Some(ref state) = ctx.state {
            response = response.with_state(state);
        }

        sender.send(&self.config.http_client, ctx, &response).await
    }

    /// Builds and sends an error response to the Verifier.
    pub async fn create_error_response(
        &self,
        ctx: &PresentationContext,
        error_code: AuthorizationErrorCode,
    ) -> Result<DirectPostResponse, Error> {
        self.create_error_response_with_sender(ctx, error_code, &DirectPostResponseSender)
            .await
    }

    /// Builds and sends an error response using a caller-provided sender.
    pub async fn create_error_response_with_sender(
        &self,
        ctx: &PresentationContext,
        error_code: AuthorizationErrorCode,
        sender: &dyn AuthzResponseSender,
    ) -> Result<DirectPostResponse, Error> {
        let mut response = AuthorizationResponse::error(error_code);
        if let Some(ref state) = ctx.state {
            response = response.with_state(state);
        }

        sender.send(&self.config.http_client, ctx, &response).await
    }

    /// Parses a raw authorization request string.
    ///
    /// Supports:
    /// - Direct JSON: `{"response_type":"vp_token",...}`
    /// - `{custom}://` URI: extracts query params and deserializes
    fn parse_authorization_request(
        &self,
        raw_request: &str,
    ) -> Result<AuthorizationRequest, Error> {
        let trimmed = raw_request.trim();

        // Try parsing as URI with query params
        if let Ok(url) = Url::parse(trimmed) {
            // Collect query params into a JSON map for deserialization
            let params: Vec<(String, String)> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();

            if params.is_empty() {
                return Err(Error::InvalidRequest(
                    "authorization request URI has no query parameters".into(),
                ));
            }

            serde_urlencoded::from_str(url.query().unwrap_or_default()).map_err(|e| {
                Error::InvalidRequest(format!(
                    "failed to deserialize authorization request from URI query: {e}"
                ))
            })
        } else {
            // Try direct JSON parsing
            serde_json::from_str(trimmed).map_err(|e| {
                Error::InvalidRequest(format!(
                    "failed to parse authorization request as JSON: {e}"
                ))
            })
        }
    }

    fn parse_authorization_request_envelope(
        &self,
        raw_request: &str,
    ) -> Result<AuthorizationRequestEnvelope, Error> {
        let trimmed = raw_request.trim();

        if let Ok(url) = Url::parse(trimmed) {
            if url.query().is_none() {
                return Err(Error::InvalidRequest(
                    "authorization request URI has no query parameters".into(),
                ));
            }
            serde_urlencoded::from_str(url.query().unwrap_or_default()).map_err(|e| {
                Error::InvalidRequest(format!(
                    "failed to deserialize authorization request envelope from URI query: {e}"
                ))
            })
        } else {
            serde_json::from_str(trimmed).map_err(|e| {
                Error::InvalidRequest(format!(
                    "failed to parse authorization request envelope as JSON: {e}"
                ))
            })
        }
    }

    async fn parse_and_resolve_authorization_request(
        &self,
        raw_request: &str,
        key_resolver: &dyn VerifierKeyResolver,
        request_uri_resolver: &dyn RequestUriResolver,
    ) -> Result<AuthorizationRequest, Error> {
        let envelope = self.parse_authorization_request_envelope(raw_request)?;

        if envelope.request_uri.is_some() || envelope.request.is_some() {
            return self
                .resolve_request_object_from_envelope(envelope, key_resolver, request_uri_resolver)
                .await;
        }

        // Unsigned request path (no request_uri, no inline request JWT).
        // Per OpenID4VP §5.9.2–5.9.3: only `redirect_uri:` prefix and pre-registered
        // clients may use unsigned requests. All other prefixes require a signed
        // Request Object.
        let client_id = ParsedClientId::parse(&envelope.client_id)?;
        if let Some(prefix) = client_id.prefix()
            && prefix != ClientIdPrefix::RedirectUri
        {
            return Err(Error::InvalidRequest(format!(
                "unsigned authorization request not allowed for client_id prefix '{}'; \
                 a signed Request Object is required",
                prefix.as_str()
            )));
        }

        self.parse_authorization_request(raw_request)
    }

    /// Resolves the Request Object from `request_uri` or inline `request` JWT.
    async fn resolve_request_object_from_envelope(
        &self,
        envelope: AuthorizationRequestEnvelope,
        key_resolver: &dyn VerifierKeyResolver,
        request_uri_resolver: &dyn RequestUriResolver,
    ) -> Result<AuthorizationRequest, Error> {
        if let Some(ref request_uri) = envelope.request_uri {
            let result = request_uri_resolver
                .resolve(
                    &self.config.http_client,
                    request_uri,
                    envelope.request_uri_method,
                    self.config.wallet_metadata.as_ref(),
                )
                .await?;
            let request_object = RequestObject::decode_and_validate(
                &result.jwt,
                &envelope.client_id,
                self.config.discovery_mode,
                key_resolver,
            )
            .await?;
            validate_wallet_nonce(&result, &request_object)?;

            Ok(request_object.claims.params)
        } else if let Some(ref inline_jwt) = envelope.request {
            let request_object = RequestObject::decode_and_validate(
                inline_jwt,
                &envelope.client_id,
                self.config.discovery_mode,
                key_resolver,
            )
            .await?;

            Ok(request_object.claims.params)
        } else {
            Err(Error::InvalidRequest(
                "authorization request envelope has neither request_uri nor request".to_string(),
            ))
        }
    }

    /// Decodes transaction_data entries from base64url-encoded strings.
    fn decode_transaction_data(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Vec<TransactionData<'static>>, Error> {
        let Some(ref td_entries) = request.transaction_data else {
            return Ok(Vec::new());
        };

        let mut result = Vec::with_capacity(td_entries.len());
        for encoded in td_entries {
            let td = TransactionData::decode(encoded).map_err(Error::InvalidTransactionData)?;
            result.push(td.into_owned());
        }
        Ok(result)
    }
}

fn validate_wallet_nonce(
    result: &RequestUriResult,
    request_object: &RequestObject,
) -> Result<(), Error> {
    let Some(expected) = result.expected_wallet_nonce.as_deref() else {
        return Ok(());
    };

    match request_object.claims.wallet_nonce.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::InvalidRequestObject(
            RequestObjectError::InvalidClaims(format!(
                "wallet_nonce mismatch: expected '{expected}', got '{actual}'"
            )),
        )),
        None => Err(Error::InvalidRequestObject(
            RequestObjectError::InvalidClaims(
                "missing required wallet_nonce claim in Request Object".to_string(),
            ),
        )),
    }
}
