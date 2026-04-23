mod error;
mod signer;

// Public Re-exports
pub use error::ClientError;
pub use signer::{
    Algorithm, Claims as ProofClaims, CryptoSigner, Header as ProofHeader, ProofSigner,
};

use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::header::CONTENT_TYPE;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::{Jitter, RetryTransientMiddleware};
use serde::Serialize;
use url::Url;

use crate::issuance::authz_details::AuthorizationDetails;
use crate::issuance::authz_request::{
    AuthorizationRequest, CodeChallengeMethod, PushedAuthorizationRequest,
};
use crate::issuance::authz_response::{AuthorizationResponse, PushedAuthorizationResponse};
use crate::issuance::authz_server_metadata::AuthorizationServerMetadata;
use crate::issuance::credential_configuration::{AlgorithmIdentifier, ProofType};
use crate::issuance::credential_offer::{
    CredentialOffer, CredentialOfferSource, CredentialOfferUri, TxCode, resolve_by_reference,
};
use crate::issuance::credential_request::{
    CredIdOrCredConfigId, CredentialRequest, DeferredCredentialRequest, Proofs,
};
use crate::issuance::credential_response::{CredentialResponse, DeferredCredentialResult};
use crate::issuance::error::{
    AuthzErrorResponse, CredentialErrorResponse, DeferredCredentialErrorResponse, Oid4vciError,
    TokenErrorResponse,
};
use crate::issuance::issuer_metadata::CredentialIssuerMetadata;
use crate::issuance::token_request::{
    AuthorizationCodeRequest, PreAuthorizedCodeRequest, TokenRequest,
};
use crate::issuance::token_response::TokenResponse;
use crate::issuance::utils::pkce::{derive_pkce_challenge, generate_pkce_verifier};

type Result<T> = std::result::Result<T, ClientError>;

const HTTP_MAX_RETRIES: u32 = 3;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;
const OAUTH_RESPONSE_TYPE: &str = "code";
const FORM_ENCODED_HEADER: &str = "application/x-www-form-urlencoded";
const JSON_HEADER: &str = "application/json";

/// Fully resolved context from a single credential offer.
#[derive(Debug, Clone)]
pub struct ResolvedOfferContext {
    pub offer: CredentialOffer,
    pub issuer_metadata: CredentialIssuerMetadata,
    pub as_metadata: AuthorizationServerMetadata,
    pub flow: IssuanceFlow,
}

/// Which grant type the orchestrator should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    PreAuthorizedCode,
}

/// Chosen issuance flow data after offer resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceFlow {
    AuthorizationCode {
        issuer_state: Option<String>,
    },
    PreAuthorizedCode {
        pre_authorized_code: String,
        tx_code: Option<TxCode>,
    },
}

impl IssuanceFlow {
    /// Returns the selected grant type for this flow.
    pub fn grant_type(&self) -> GrantType {
        match self {
            Self::AuthorizationCode { .. } => GrantType::AuthorizationCode,
            Self::PreAuthorizedCode { .. } => GrantType::PreAuthorizedCode,
        }
    }

    /// Returns the tx code requirements when using pre-authorized code flow.
    pub fn tx_code_spec(&self) -> Option<&TxCode> {
        match self {
            Self::AuthorizationCode { .. } => None,
            Self::PreAuthorizedCode { tx_code, .. } => tx_code.as_ref(),
        }
    }

    /// Returns true when the flow requires a user-provided transaction code.
    pub fn tx_code_required(&self) -> bool {
        self.tx_code_spec().is_some()
    }
}

/// Result of building the authorization URL.
#[derive(Debug)]
pub struct AuthorizationUrlResult {
    pub authz_url: Url,
    pub pkce_verifier: String,
}

/// Parsed authorization callback outcome.
#[derive(Debug)]
pub enum AuthorizationCallback {
    Success(AuthorizationResponse),
    Error(Oid4vciError<AuthzErrorResponse>),
}

/// Notification event value for notification endpoint calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialDeleted,
    CredentialFailure,
}

/// Configuration for the OID4VCI client.
#[derive(Debug, Clone)]
pub struct Config {
    /// The wallet's OAuth 2.0 `client_id` as registered at the issuer AS.
    pub client_id: String,
    /// The redirect URI registered with the issuer AS.
    pub redirect_uri: Url,
    /// Total timeout for each request.
    pub timeout: Duration,
    /// Optional user-agent value to send with every request.
    pub user_agent: Option<String>,
    /// Accept untrusted hosts (testing only).
    pub accept_untrusted_hosts: bool,
}

impl Config {
    /// Creates a new configuration with the given client ID and redirect URI.
    ///
    /// Defaults:
    /// - timeout: 10 seconds
    /// - user_agent: None
    /// - accept_untrusted_hosts: false
    pub fn new(client_id: impl Into<String>, redirect_uri: Url) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri,
            timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
            user_agent: None,
            accept_untrusted_hosts: false,
        }
    }

    /// Sets the total request timeout.
    ///
    /// Defaults to 10 seconds.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Sets a custom user-agent header value.
    pub fn user_agent(self, user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: Some(user_agent.into()),
            ..self
        }
    }

    /// Enables or disables accepting untrusted hosts.
    ///
    /// This should only be enabled in test environments.
    pub fn accept_untrusted_hosts(self, accept_untrusted_hosts: bool) -> Self {
        Self {
            accept_untrusted_hosts,
            ..self
        }
    }
}

/// High-level OID4VCI orchestration client.
///
/// The client covers:
/// - Credential offer resolution (inline + by-reference)
/// - Issuer and AS metadata discovery with dual well-known path fallback
/// - Authorization URL construction (PAR-first, PKCE-mandatory)
/// - Token exchange (authorization code + pre-authorized code flows)
/// - c_nonce retrieval from the nonce endpoint
/// - Credential request with holder-binding proof
/// - Deferred credential polling
/// - Notification (optional, best-effort)
#[derive(Debug, Clone)]
pub struct Oid4vciClient {
    config: Arc<Config>,
    http_client: ClientWithMiddleware,
}

impl Oid4vciClient {
    /// Creates a new client with custom HTTP options for the internal request client.
    pub fn new_with_http_options(config: Config) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder()
            .jitter(Jitter::Bounded)
            .build_with_max_retries(HTTP_MAX_RETRIES);

        let mut inner_client_builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .tls_backend_rustls()
            .tls_danger_accept_invalid_hostnames(config.accept_untrusted_hosts)
            .https_only(true);

        if let Some(ref user_agent) = config.user_agent {
            inner_client_builder = inner_client_builder.user_agent(user_agent);
        }

        let inner_client = inner_client_builder
            .build()
            .map_err(|e| ClientError::configuration(format!("failed to build HTTP client: {e}")))?;

        let http_client = ClientBuilder::new(inner_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Self {
            config: Arc::new(config),
            http_client,
        })
    }

    /// Returns the underlying HTTP client.
    pub fn http_client(&self) -> &ClientWithMiddleware {
        &self.http_client
    }

    /// Resolve a raw credential offer string into a typed `CredentialOffer`.
    ///
    /// Handles all two input forms:
    /// - `openid-credential-offer://?credential_offer=<inline-json>`
    /// - `openid-credential-offer://?credential_offer_uri=<https-url>`
    pub async fn resolve_offer(&self, raw: &str) -> Result<CredentialOffer> {
        let uri = CredentialOfferUri::from_offer_link(raw)?;

        match uri.source {
            CredentialOfferSource::ByValue(offer) => Ok(offer),
            CredentialOfferSource::ByReference(url) => {
                // For by-reference offers, we need to fetch them
                resolve_by_reference(&url, &self.http_client)
                    .await
                    .map_err(ClientError::from)
            }
        }
    }

    /// Fetch the credential issuer metadata from
    /// `{issuer}/.well-known/openid-credential-issuer`.
    ///
    /// Per OID4VCI §12.2.2, the path component of the issuer URL (if any) is
    /// appended after the well-known prefix.
    pub async fn fetch_issuer_metadata(
        &self,
        credential_issuer: &Url,
    ) -> Result<CredentialIssuerMetadata> {
        // Construct the well-known URL per OID4VCI §12.2.2
        let url = well_known_issuer_metadata_url(credential_issuer);

        let response = self
            .http_client
            .get(url)
            .header(CONTENT_TYPE, JSON_HEADER)
            .send()
            .await
            .map_err(|e| ClientError::http("failed to fetch issuer metadata", e))?;

        if !response.status().is_success() {
            return Err(http_error_response(response).await);
        }

        let metadata = response
            .json::<CredentialIssuerMetadata>()
            .await
            .map_err(|e| ClientError::InvalidResponse {
                message: format!("failed to parse issuer metadata: {e}").into(),
            })?;

        // Validate the metadata
        metadata.validate()?;
        Ok(metadata)
    }

    /// Fetch authorization server metadata.
    ///
    /// Tries `/.well-known/oauth-authorization-server{path}` first (RFC 8414 §3),
    /// then falls back to `{issuer}/.well-known/openid-configuration` (RFC 8414 §5).
    pub async fn fetch_as_metadata(
        &self,
        credential_issuer: &Url,
        issuer_metadata: &CredentialIssuerMetadata,
        offer: &CredentialOffer,
    ) -> Result<AuthorizationServerMetadata> {
        // Determine the AS URL
        let as_url = resolve_as_url(credential_issuer, issuer_metadata, offer)?;

        // Try RFC 8414 §3 well-known path first
        let rfc8414_url = well_known_oauth_as_url(&as_url);
        // Try the primary endpoint
        let response = self
            .http_client
            .get(rfc8414_url)
            .send()
            .await
            .map_err(|e| ClientError::http("failed to fetch AS metadata", e))?;

        if response.status().is_success() {
            let metadata = response
                .json::<AuthorizationServerMetadata>()
                .await
                .map_err(|e| ClientError::InvalidResponse {
                    message: format!("failed to parse AS metadata: {e}").into(),
                })?;
            metadata.validate()?;
            return Ok(metadata);
        }
        // Fall back only on 4xx (endpoint does not exist at this path)
        if !response.status().is_client_error() {
            return Err(http_error_response(response).await);
        }

        // Fallback: openid-configuration (RFC 8414 §5 / OIDC Discovery)
        let oidc_url = well_known_oidc_configuration_url(&as_url);
        let response = self
            .http_client
            .get(oidc_url)
            .send()
            .await
            .map_err(|e| ClientError::http("failed to fetch AS metadata (fallback)", e))?;

        if !response.status().is_success() {
            return Err(http_error_response(response).await);
        }

        let metadata = response
            .json::<AuthorizationServerMetadata>()
            .await
            .map_err(|e| ClientError::InvalidResponse {
                message: format!("failed to parse AS metadata: {e}").into(),
            })?;

        metadata.validate()?;
        Ok(metadata)
    }

    /// Resolves the provided raw credential offer into the fully resolved offer context.
    ///
    /// You can specify a preferred grant type to use when multiple grant types are present
    /// in the offer.
    ///
    /// Supported `raw_offer` forms:
    /// - Full `openid-credential-offer://` URI
    /// - Query string containing `credential_offer` or `credential_offer_uri`
    pub async fn resolve_offer_with_metadata(
        &self,
        raw_offer: &str,
        preferred: Option<GrantType>,
    ) -> Result<ResolvedOfferContext> {
        let offer = self.resolve_offer(raw_offer).await?;
        let issuer_metadata = self.fetch_issuer_metadata(&offer.credential_issuer).await?;
        let as_metadata = self
            .fetch_as_metadata(&offer.credential_issuer, &issuer_metadata, &offer)
            .await?;
        let flow_type = self.determine_flow(&offer, &as_metadata, preferred)?;

        Ok(ResolvedOfferContext {
            offer,
            issuer_metadata,
            as_metadata,
            flow: flow_type,
        })
    }

    /// Build the authorization URL and PKCE parameters for the authorization
    /// code flow.
    ///
    /// Uses Pushed Authorization Request (PAR) when the AS supports it; falls back
    /// to a regular authorization URL.
    pub async fn build_authorization_url(
        &self,
        context: &ResolvedOfferContext,
        state: impl Into<String>,
        credential_config_ids: &[String],
    ) -> Result<AuthorizationUrlResult> {
        // Verify this is an authorization code flow context
        let issuer_state = match &context.flow {
            IssuanceFlow::AuthorizationCode { issuer_state } => issuer_state.to_owned(),
            _ => {
                return Err(ClientError::Configuration {
                    message: "cannot build authorization URL for pre-authorized code flow".into(),
                });
            }
        };

        let authz_endpoint = context
            .as_metadata
            .authorization_endpoint
            .as_ref()
            .ok_or_else(|| ClientError::Configuration {
                message: "authorization server does not have an authorization endpoint".into(),
            })?;

        // Include authorization_details so the AS can return credential_identifiers
        // in the token response per §6.2
        let authz_details = build_authorization_details(context, credential_config_ids)?;

        // Generate PKCE parameters
        let pkce_verifier = generate_pkce_verifier();
        let code_challenge = derive_pkce_challenge(&pkce_verifier);

        // Build the authorization request
        let authz_request = AuthorizationRequest {
            response_type: OAUTH_RESPONSE_TYPE.into(),
            client_id: self.config.client_id.clone(),
            redirect_uri: Some(self.config.redirect_uri.clone()),
            state: Some(state.into()),
            scope: None,
            resource: None,
            issuer_state,
            authorization_details: Some(authz_details),
            code_challenge: Some(code_challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
        };

        let authz_url = if context
            .as_metadata
            .pushed_authorization_request_endpoint
            .is_some()
        {
            // PAR is advertised, use it.
            let par_response = self.send_par(context, &authz_request).await?;
            build_par_redirect_url(authz_endpoint, &self.config.client_id, par_response)?
        } else {
            build_plain_authz_url(authz_endpoint, authz_request)?
        };

        Ok(AuthorizationUrlResult {
            authz_url,
            pkce_verifier,
        })
    }

    /// Parses authorization callback from redirect URI into success/error result.
    pub fn parse_authz_callback(&self, redirect_uri: &str) -> Result<AuthorizationCallback> {
        let url = Url::parse(redirect_uri)
            .map_err(|e| ClientError::validation(format!("invalid redirect uri: {e}")))?;
        let query = url.query().unwrap_or_default();

        if url.query_pairs().any(|(k, _)| k == "error") {
            let error =
                serde_urlencoded::from_str(query).map_err(|e| ClientError::InvalidResponse {
                    message: format!("failed to parse authorization error: {e}").into(),
                })?;
            return Ok(AuthorizationCallback::Error(error));
        }

        let response =
            serde_urlencoded::from_str(query).map_err(|e| ClientError::InvalidResponse {
                message: format!("failed to parse authorization response: {e}").into(),
            })?;
        Ok(AuthorizationCallback::Success(response))
    }

    /// Exchange an authorization code for an access token (authorization code flow).
    pub async fn exchange_authorization_code(
        &self,
        context: &ResolvedOfferContext,
        code: impl Into<String>,
        pkce_verifier: impl Into<String>,
        credential_config_ids: &[String],
    ) -> Result<TokenResponse> {
        // Verify this is an authorization code flow
        if !matches!(context.flow, IssuanceFlow::AuthorizationCode { .. }) {
            return Err(ClientError::validation(
                "cannot exchange authorization code in pre-authorized code flow",
            ));
        }

        let token_endpoint = context.as_metadata.token_endpoint.as_ref().ok_or_else(|| {
            ClientError::configuration("authorization server does not have a token endpoint")
        })?;

        // Include authorization_details so the AS can return credential_identifiers
        // in the token response per §6.2
        let authz_details = build_authorization_details(context, credential_config_ids)?;

        let request = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: Some(self.config.redirect_uri.clone()),
            client_id: self.config.client_id.clone(),
            code_verifier: Some(pkce_verifier.into()),
            authorization_details: Some(authz_details),
        });
        self.post_token_request(token_endpoint, &request).await
    }

    /// Exchange a pre-authorized code for an access token.
    /// `tx_code` is included when the issuer requires one (OID4VCI §6.1).
    pub async fn exchange_pre_authorized_code(
        &self,
        context: &ResolvedOfferContext,
        pre_authorized_code: impl Into<String>,
        tx_code: Option<impl Into<String>>,
        credential_config_ids: &[String],
    ) -> Result<TokenResponse> {
        // Verify this is a pre-authorized code flow
        if !matches!(context.flow, IssuanceFlow::PreAuthorizedCode { .. }) {
            return Err(ClientError::validation(
                "cannot exchange tx_code in authorization code flow",
            ));
        }

        let token_endpoint = context.as_metadata.token_endpoint.as_ref().ok_or_else(|| {
            ClientError::configuration("authorization server does not have a token endpoint")
        })?;

        // Check if AS allows anonymous access
        let client_id = if context.as_metadata.allows_anonymous_pre_authorized_grant() {
            None
        } else {
            Some(self.config.client_id.clone())
        };

        // Include authorization_details so the AS can return credential_identifiers
        // in the token response per §6.2
        let authz_details = build_authorization_details(context, credential_config_ids)?;

        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: pre_authorized_code.into(),
            client_id,
            tx_code: tx_code.map(|t| t.into()),
            authorization_details: Some(authz_details),
        });
        self.post_token_request(token_endpoint, &request).await
    }

    /// Fetch a fresh `c_nonce` from the issuer's nonce endpoint.
    pub async fn fetch_nonce(&self, nonce_endpoint: &Url) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct NonceResponse {
            c_nonce: String,
        }

        let response = self
            .http_client
            .post(nonce_endpoint.as_str())
            .send()
            .await
            .map_err(|e| ClientError::http("nonce request failed", e))?;

        if !response.status().is_success() {
            return Err(http_error_response(response).await);
        }

        let nonce_response: NonceResponse =
            response
                .json()
                .await
                .map_err(|e| ClientError::InvalidResponse {
                    message: format!("failed to parse nonce response: {e}").into(),
                })?;
        Ok(nonce_response.c_nonce)
    }

    /// Request a credential from the issuer's credential endpoint.
    ///
    /// Optionally builds the holder-binding proof using `signer`,
    /// submits the credential request.
    pub async fn request_credential<S: ProofSigner>(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        credential_identifier: impl Into<String>,
        credential_config_id: &str,
        signer: &S,
    ) -> Result<CredentialResponse> {
        let is_anonymous = context.as_metadata.allows_anonymous_pre_authorized_grant()
            && matches!(context.flow, IssuanceFlow::PreAuthorizedCode { .. });

        let c_nonce = self.resolve_nonce(&context.issuer_metadata).await?;
        let proofs = self
            .build_proofs(
                context,
                c_nonce.as_deref(),
                is_anonymous,
                credential_config_id,
                signer,
            )
            .await?;

        let id = CredIdOrCredConfigId::credential_identifier(credential_identifier);
        let mut request = CredentialRequest::new(id);
        if let Some(p) = proofs {
            request = request.with_proofs(p);
        }

        self.post_credential_request(context, access_token, &request)
            .await
    }

    /// Request all credentials authorized by the token response.
    ///
    /// The caller is responsible for handling individual failures (e.g. deferred
    /// issuance on some credentials while others succeed).
    pub async fn request_credentials<S: ProofSigner>(
        &self,
        context: &ResolvedOfferContext,
        token: &TokenResponse,
        signer: &S,
    ) -> Result<Vec<CredentialResponse>> {
        let resolved = resolve_credential_ids(token)?;
        let mut futures = FuturesUnordered::new();
        let token = &token.access_token;
        let total: usize = resolved.iter().map(|(_, ids)| ids.len()).sum();
        let mut results = Vec::with_capacity(total);

        for (config_id, identifiers) in resolved {
            for id in identifiers {
                futures.push(self.request_credential(context, token, id, &config_id, signer));
            }
        }

        while let Some(res) = futures.next().await {
            results.push(res?);
        }
        Ok(results)
    }

    /// Polls the deferred credential endpoint for a single transaction id.
    pub async fn poll_deferred_credential(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        transaction_id: impl Into<String>,
    ) -> Result<DeferredCredentialResult> {
        let endpoint = context
            .issuer_metadata
            .deferred_credential_endpoint
            .as_ref()
            .ok_or(ClientError::configuration(
                "Missing deferred credential endpoint",
            ))?;

        let request = DeferredCredentialRequest {
            transaction_id: transaction_id.into(),
            credential_response_encryption: None,
        };

        let response = self
            .http_client
            .post(endpoint.as_str())
            .bearer_auth(access_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| ClientError::http("Failed to poll deferred credential", e))?;

        if !response.status().is_success() {
            // Try to parse as deferred credential error
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check if it's a deferred credential error
            if let Ok(error) =
                serde_json::from_str::<Oid4vciError<DeferredCredentialErrorResponse>>(&body)
            {
                return Err(ClientError::DeferredCredential(error));
            }
            return Err(ClientError::http_response(status.as_u16(), body));
        }

        let result = response
            .json::<DeferredCredentialResult>()
            .await
            .map_err(|e| ClientError::InvalidResponse {
                message: format!("Failed to parse deferred credential response: {e}").into(),
            })?;
        Ok(result)
    }

    /// Send a credential storage notification to the issuer.
    ///
    /// Failures are logged but do not propagate, the notification endpoint
    /// is optional and its failure must not break the issuance flow.
    pub async fn send_notification(
        &self,
        notification_endpoint: &Url,
        access_token: impl Into<String>,
        notification_id: impl Into<String>,
        event: NotificationEvent,
        event_description: Option<impl Into<String>>,
    ) {
        #[derive(Serialize)]
        struct NotificationRequest {
            notification_id: String,
            event: NotificationEvent,
            #[serde(skip_serializing_if = "Option::is_none")]
            event_description: Option<String>,
        }

        let request = NotificationRequest {
            notification_id: notification_id.into(),
            event,
            event_description: event_description.map(|d| d.into()),
        };

        let _ = self
            .http_client
            .post(notification_endpoint.as_str())
            .bearer_auth(access_token.into())
            .json(&request)
            .send()
            .await;
    }

    /// Determine the issuance flow based on the offer and metadata.
    fn determine_flow(
        &self,
        offer: &CredentialOffer,
        as_metadata: &AuthorizationServerMetadata,
        preferred_grant: Option<GrantType>,
    ) -> Result<IssuanceFlow> {
        let grants = offer.grants.as_ref();
        let has_any_grants = grants
            .map(|g| g.authorization_code.is_some() || g.pre_authorized_code.is_some())
            .unwrap_or(false);

        if !has_any_grants {
            // Spec §4.1.1: grants absent or empty: MUST use AS metadata
            return determine_flow_from_as_metadata(as_metadata);
        }

        let authz = grants.and_then(|g| g.authorization_code.as_ref());
        let pre_auth = grants.and_then(|g| g.pre_authorized_code.as_ref());

        match (authz, pre_auth) {
            // Both present — surface the ambiguity
            (Some(a), Some(p)) => match preferred_grant {
                Some(GrantType::AuthorizationCode) => Ok(IssuanceFlow::AuthorizationCode {
                    issuer_state: a.issuer_state.clone(),
                }),
                Some(GrantType::PreAuthorizedCode) => Ok(IssuanceFlow::PreAuthorizedCode {
                    pre_authorized_code: p.pre_authorized_code.clone(),
                    tx_code: p.tx_code.clone(),
                }),
                None => Ok(IssuanceFlow::PreAuthorizedCode {
                    pre_authorized_code: p.pre_authorized_code.clone(),
                    tx_code: p.tx_code.clone(),
                }),
            },

            (Some(a), None) => Ok(IssuanceFlow::AuthorizationCode {
                issuer_state: a.issuer_state.clone(),
            }),

            (None, Some(p)) => Ok(IssuanceFlow::PreAuthorizedCode {
                pre_authorized_code: p.pre_authorized_code.clone(),
                tx_code: p.tx_code.clone(),
            }),

            // Unreachable: has_any_grants would be false for (None, None)
            (None, None) => Err(ClientError::NoSupportedGrantType),
        }
    }

    /// Send Pushed Authorization Request (PAR).
    async fn send_par(
        &self,
        context: &ResolvedOfferContext,
        request: &AuthorizationRequest,
    ) -> Result<PushedAuthorizationResponse> {
        let par_endpoint = context
            .as_metadata
            .pushed_authorization_request_endpoint
            .as_ref()
            .ok_or_else(|| ClientError::configuration("PAR endpoint not available"))?;

        let body = serde_urlencoded::to_string(request)
            .map_err(|e| ClientError::internal(format!("Failed to serialize PAR request: {e}")))?;

        let response = self
            .http_client
            .post(par_endpoint.as_str())
            .header(CONTENT_TYPE, FORM_ENCODED_HEADER)
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::http("PAR request failed", e))?;

        if !response.status().is_success() {
            // Try to parse as OAuth error
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            // Check if it's a standard OAuth error
            if let Ok(error) = serde_json::from_str::<Oid4vciError<AuthzErrorResponse>>(&body) {
                return Err(ClientError::Authorization(error));
            }
            return Err(ClientError::http_response(status.as_u16(), body));
        }

        let par_response = response
            .json::<PushedAuthorizationResponse>()
            .await
            .map_err(|e| ClientError::InvalidResponse {
                message: format!("failed to parse PAR response: {e}").into(),
            })?;
        Ok(par_response)
    }

    async fn post_token_request<T: serde::Serialize>(
        &self,
        token_endpoint: &Url,
        request: &T,
    ) -> Result<TokenResponse> {
        let body = serde_urlencoded::to_string(request).map_err(|e| {
            ClientError::internal(format!("Failed to serialize token request: {e}"))
        })?;

        let response = self
            .http_client
            .post(token_endpoint.as_str())
            .header(CONTENT_TYPE, FORM_ENCODED_HEADER)
            .body(body)
            .send()
            .await
            .map_err(|e| ClientError::http("token request failed", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Try to parse as OAuth error response
            if let Ok(error) = serde_json::from_str::<Oid4vciError<TokenErrorResponse>>(&body) {
                return Err(ClientError::Token(error));
            }
            return Err(ClientError::http_response(status.as_u16(), body));
        }

        // Parse successful response
        let token_response = response
            .json()
            .await
            .map_err(|e| ClientError::InvalidResponse {
                message: format!("failed to parse token response: {e}").into(),
            })?;
        Ok(token_response)
    }

    async fn build_proofs<S: ProofSigner>(
        &self,
        context: &ResolvedOfferContext,
        c_nonce: Option<&str>,
        is_anonymous: bool,
        credential_config_id: &str,
        signer: &S,
    ) -> Result<Option<Proofs>> {
        if !should_sign_proof(context, credential_config_id, signer)? {
            return Ok(None);
        }

        let client_id = if is_anonymous {
            None
        } else {
            Some(self.config.client_id.to_owned())
        };

        let claims = ProofClaims {
            aud: context.offer.credential_issuer.to_string(),
            iat: time::UtcDateTime::now().unix_timestamp(),
            iss: client_id,
            nonce: c_nonce.map(|n| n.to_owned()),
        };

        let jwt = signer.sign(&claims)?;
        Ok(Some(Proofs::jwt([jwt])))
    }

    async fn post_credential_request(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        let response = self
            .http_client
            .post(context.issuer_metadata.credential_endpoint.as_str())
            .bearer_auth(access_token)
            .json(request)
            .send()
            .await
            .map_err(|e| ClientError::http("credential request failed", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if let Ok(error) = serde_json::from_str::<Oid4vciError<CredentialErrorResponse>>(&body)
            {
                return Err(ClientError::Credential(error));
            }
            return Err(ClientError::http_response(status.as_u16(), body));
        }

        let credential_response = response.json::<CredentialResponse>().await.map_err(|e| {
            ClientError::InvalidResponse {
                message: format!("failed to parse credential response: {e}").into(),
            }
        })?;
        Ok(credential_response)
    }

    /// Resolve the `c_nonce` to use for proof construction.
    ///
    /// Per §8.2 and §7: priority order is:
    /// 1. Fresh nonce from `nonce_endpoint` (if advertised in issuer metadata)
    /// 2. `None` — issuer does not require a nonce
    async fn resolve_nonce(
        &self,
        issuer_metadata: &CredentialIssuerMetadata,
    ) -> Result<Option<String>> {
        if let Some(endpoint) = &issuer_metadata.nonce_endpoint {
            return Ok(Some(self.fetch_nonce(endpoint).await?));
        }
        Ok(None)
    }
}

/// Resolve the correct Authorization Server URL for this offer and flow.
pub fn resolve_as_url(
    credential_issuer: &Url,
    issuer_metadata: &CredentialIssuerMetadata,
    offer: &CredentialOffer,
) -> Result<Url> {
    let servers = issuer_metadata
        .authorization_servers
        .as_deref()
        .unwrap_or_default();

    // Extract the authorization_server hint from the relevant grant
    let hint = extract_authorization_server_hint(offer);

    if let Some(hint) = hint {
        let matched = servers.iter().find(|s| *s == hint).ok_or_else(|| {
            ClientError::validation(format!(
                "authorization_server hint '{hint}' does not match any entry \
                in the issuer's authorization_servers array"
            ))
        })?;
        return Ok(matched.to_owned());
    }

    // No hint, resolve from issuer metadata
    match servers {
        [] => Ok(credential_issuer.to_owned()),
        [single] => Ok(single.to_owned()),
        multiple => {
            // No match or no grant type known, fall back to first entry
            // Should normally never happen in practice
            Ok(multiple[0].to_owned())
        }
    }
}

/// Extract the `authorization_server` hint from the grant.
fn extract_authorization_server_hint(offer: &CredentialOffer) -> Option<&Url> {
    let grants = offer.grants.as_ref()?;
    grants
        .pre_authorized_code
        .as_ref()
        .and_then(|p| p.authorization_server.as_ref())
        .or_else(|| {
            grants
                .authorization_code
                .as_ref()
                .and_then(|a| a.authorization_server.as_ref())
        })
}

/// Determine flow from AS metadata when the credential offer contains no grants.
///
/// Per §4.1.1: the wallet MUST check `grant_types_supported` to determine what
/// the AS can handle.
fn determine_flow_from_as_metadata(
    as_metadata: &AuthorizationServerMetadata,
) -> Result<IssuanceFlow> {
    const AUTHZ_CODE: &str = "authorization_code";

    let supported = as_metadata
        .grant_types_supported
        .as_deref()
        .unwrap_or_default();

    let supports_authz_code = supported.iter().any(|g| g == AUTHZ_CODE)
        // If grant_types_supported is absent the AS implicitly supports
        // authorization_code per RFC 8414 §2.
        || as_metadata.grant_types_supported.is_none();

    if supports_authz_code {
        Ok(IssuanceFlow::AuthorizationCode { issuer_state: None })
    } else {
        Err(ClientError::NoSupportedGrantType)
    }
}

fn selected_credential_config_ids(
    context: &ResolvedOfferContext,
    selected_config_ids: &[String],
) -> Result<Vec<String>> {
    if selected_config_ids.is_empty() {
        Ok(context.offer.credential_configuration_ids.clone())
    } else {
        let ids = selected_config_ids.to_vec();
        for id in &ids {
            if !context.offer.credential_configuration_ids.contains(id) {
                return Err(ClientError::UnknownCredentialConfiguration { id: id.clone() });
            }
        }
        Ok(ids)
    }
}

fn build_authorization_details(
    context: &ResolvedOfferContext,
    selected_config_ids: &[String],
) -> Result<Vec<AuthorizationDetails>> {
    let selected_ids = selected_credential_config_ids(context, selected_config_ids)?;
    let include_locations = context.issuer_metadata.authorization_servers.is_some();

    selected_ids
        .iter()
        .map(|id| {
            let detail = if include_locations {
                AuthorizationDetails::for_configuration(id)
                    .with_locations(vec![context.issuer_metadata.credential_issuer.clone()])
            } else {
                AuthorizationDetails::for_configuration(id)
            };
            Ok(detail)
        })
        .collect()
}

/// Negotiate the proof algorithm for a credential request.
fn should_sign_proof<S: ProofSigner>(
    context: &ResolvedOfferContext,
    credential_config_id: &str,
    signer: &S,
) -> Result<bool> {
    let config = context
        .issuer_metadata
        .credential_configurations_supported
        .get(credential_config_id)
        .ok_or_else(|| ClientError::UnknownCredentialConfiguration {
            id: credential_config_id.into(),
        })?;

    // No proof required
    let Some(proof_types) = config.proof_types_supported.as_ref() else {
        return Ok(false);
    };

    let proof_type = proof_types.get(&ProofType::Jwt).ok_or_else(|| {
        ClientError::configuration(format!(
            "credential configuration '{credential_config_id}' does not support 'jwt' proofs"
        ))
    })?;

    let signer_alg = signer.algorithm();
    if proof_type
        .proof_signing_alg_values_supported
        .iter()
        .any(|id| id.matches(signer_alg))
    {
        return Ok(true);
    }

    Err(ClientError::configuration(format!(
        "no compatible jwt proof signing algorithm for configuration '{credential_config_id}'"
    )))
}

pub fn resolve_credential_ids(token: &TokenResponse) -> Result<Vec<(&str, &[String])>> {
    let details =
        token
            .authorization_details
            .as_ref()
            .ok_or_else(|| ClientError::InvalidResponse {
                message: "missing authorization_details in token response".into(),
            })?;

    let mut result = Vec::with_capacity(details.len());

    for detail in details {
        let Some(ids) = detail.credential_identifiers.as_deref() else {
            continue;
        };

        if ids.is_empty() {
            return Err(ClientError::InvalidResponse {
                message: format!(
                    "authorization_details entry for '{}' contains empty credential_identifiers",
                    detail.credential_configuration_id
                )
                .into(),
            });
        }
        result.push((detail.credential_configuration_id.as_str(), ids));
    }

    if result.is_empty() {
        return Err(ClientError::InvalidResponse {
            message: "no credential_identifiers found in authorization_details".into(),
        });
    }
    Ok(result)
}

/// Build the minimal PAR redirect URL.
fn build_par_redirect_url(
    authz_endpoint: &Url,
    client_id: &str,
    par_response: PushedAuthorizationResponse,
) -> Result<Url> {
    let mut url = authz_endpoint.clone();
    let query_string = serde_urlencoded::to_string(PushedAuthorizationRequest {
        client_id: client_id.to_owned(),
        request_uri: par_response.request_uri,
    })
    .map_err(|e| ClientError::internal(format!("failed to serialize PAR request: {e}")))?;
    url.set_query(Some(&query_string));
    Ok(url)
}

/// Build a plain authorization URL with all parameters inline.
fn build_plain_authz_url(authz_endpoint: &Url, request: AuthorizationRequest) -> Result<Url> {
    let mut url = authz_endpoint.clone();
    let query_string = serde_urlencoded::to_string(request).map_err(|e| {
        ClientError::internal(format!("failed to serialize authorization request: {e}"))
    })?;
    url.set_query(Some(&query_string));
    Ok(url)
}

fn well_known_issuer_metadata_url(issuer: &Url) -> Url {
    let mut url = issuer.clone();
    let path = issuer.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/openid-credential-issuer{path}"));
    url
}

fn well_known_oauth_as_url(as_url: &Url) -> Url {
    let mut url = as_url.clone();
    let path = as_url.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/oauth-authorization-server{path}"));
    url
}

fn well_known_oidc_configuration_url(as_url: &Url) -> Url {
    let mut url = as_url.clone();
    let path = as_url.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/openid-configuration{path}"));
    url
}

async fn http_error_response(response: reqwest::Response) -> ClientError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    ClientError::http_response(status, body)
}

impl AlgorithmIdentifier {
    pub fn matches(&self, alg: Algorithm) -> bool {
        match self {
            AlgorithmIdentifier::String(s) => s == alg.as_str(),
            AlgorithmIdentifier::Integer(n) => {
                // COSE mapping
                match (*n, alg) {
                    (-7, Algorithm::ES256) => true,
                    (-7, Algorithm::ES256K) => true,
                    (-9, Algorithm::ES256) => true,
                    (-35, Algorithm::ES384) => true,
                    (-36, Algorithm::ES512) => true,
                    (-8, Algorithm::EdDSA) => true,
                    (-37, Algorithm::PS256) => true,
                    (-38, Algorithm::PS384) => true,
                    (-39, Algorithm::PS512) => true,
                    (-257, Algorithm::RS256) => true,
                    (-258, Algorithm::RS384) => true,
                    (-259, Algorithm::RS512) => true,
                    _ => false,
                }
            }
        }
    }
}
