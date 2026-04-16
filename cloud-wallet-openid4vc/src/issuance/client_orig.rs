//! OID4VCI orchestration client for backend-driven issuance flows.
//!
//! This client is designed for a split architecture where:
//! - Frontend scans/provides a credential offer and captures user consent.
//! - Backend orchestrates all issuer-facing OID4VCI calls.

use std::collections::HashSet;

use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;
use url::Url;

use crate::errors::{Error as DomainError, ErrorKind};
use crate::issuance::authz_details::AuthorizationDetails;
use crate::issuance::authz_request::{AuthorizationRequest, CodeChallengeMethod};
use crate::issuance::authz_response::AuthorizationResponse;
use crate::issuance::authz_server_metadata::AuthorizationServerMetadata;
use crate::issuance::credential_configuration::{CredentialConfiguration, CredentialDisplay};
use crate::issuance::credential_offer::{
    CredentialOffer, CredentialOfferSource, CredentialOfferUri, InputMode, TxCode,
    resolve_by_reference,
};
use crate::issuance::credential_request::CredentialRequest;
use crate::issuance::credential_response::{CredentialResponse, DeferredCredentialResult};
use crate::issuance::error::{
    AuthzErrorResponse, CredentialErrorResponse, DeferredCredentialErrorResponse,
    NotificationErrorResponse, Oid4vciError, TokenErrorResponse,
};
use crate::issuance::issuer_metadata::CredentialIssuerMetadata;
use crate::issuance::token_request::{
    AuthorizationCodeRequest, PreAuthorizedCodeRequest, TokenRequest,
};
use crate::issuance::token_response::TokenResponse;

const WELL_KNOWN_OPENID_CREDENTIAL_ISSUER: &str = "openid-credential-issuer";
const WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER: &str = "oauth-authorization-server";
const WELL_KNOWN_OPENID_CONFIGURATION: &str = "openid-configuration";
const PRE_AUTHORIZED_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// Client-level error for OID4VCI orchestration operations.
#[derive(Debug, Error)]
pub enum Oid4vciClientError {
    #[error(transparent)]
    Domain(#[from] DomainError),

    #[error("HTTP request to '{endpoint}' failed")]
    Http {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("unexpected HTTP status {status} from '{endpoint}': {body}")]
    UnexpectedStatus {
        endpoint: String,
        status: reqwest::StatusCode,
        body: String,
    },

    #[error("invalid JSON response from '{endpoint}': {source}")]
    InvalidJson {
        endpoint: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("authorization server is ambiguous; issuer metadata lists multiple servers")]
    AmbiguousAuthorizationServer,

    #[error("authorization server '{requested}' is not listed in issuer metadata")]
    UnknownAuthorizationServer { requested: String },

    #[error("selected flow is unsupported by the current operation")]
    UnsupportedFlowForOperation,

    #[error("authorization endpoint is missing in authorization server metadata")]
    MissingAuthorizationEndpoint,

    #[error("token endpoint is missing in authorization server metadata")]
    MissingTokenEndpoint,

    #[error("deferred credential endpoint is missing in issuer metadata")]
    MissingDeferredCredentialEndpoint,

    #[error("nonce endpoint is missing in issuer metadata")]
    MissingNonceEndpoint,

    #[error("notification endpoint is missing in issuer metadata")]
    MissingNotificationEndpoint,

    #[error("pushed authorization request endpoint is missing in authorization server metadata")]
    MissingPushedAuthorizationRequestEndpoint,

    #[error("pushed authorization request endpoint returned error: {0}")]
    PushedAuthorizationRequestEndpointError(Oid4vciError<String>),

    #[error("authorization server requires PAR but request mode is query parameters")]
    PushedAuthorizationRequestRequired,

    #[error("offer does not contain grant data required for selected flow")]
    MissingGrantData,

    #[error("credential offer references unknown credential configuration id '{id}'")]
    UnknownCredentialConfigurationId { id: String },

    #[error("transaction code is required for this flow")]
    MissingTxCode,

    #[error(
        "client_id is required for pre-authorized token request unless anonymous access is supported"
    )]
    MissingClientIdForPreAuthorizedTokenRequest,

    #[error("transaction code must contain only ASCII digits")]
    InvalidTxCodeFormat,

    #[error("transaction code length must be exactly {expected}")]
    InvalidTxCodeLength { expected: u32 },

    #[error("token endpoint returned protocol error: {0}")]
    TokenEndpointError(Oid4vciError<TokenErrorResponse>),

    #[error("token endpoint returned unknown protocol error: {0}")]
    TokenEndpointUnknownError(Oid4vciError<String>),

    #[error("credential endpoint returned protocol error: {0}")]
    CredentialEndpointError(Oid4vciError<CredentialErrorResponse>),

    #[error("credential endpoint returned unknown protocol error: {0}")]
    CredentialEndpointUnknownError(Oid4vciError<String>),

    #[error("deferred credential endpoint returned protocol error: {0}")]
    DeferredCredentialEndpointError(Oid4vciError<DeferredCredentialErrorResponse>),

    #[error("deferred credential endpoint returned unknown protocol error: {0}")]
    DeferredCredentialEndpointUnknownError(Oid4vciError<String>),

    #[error("notification endpoint returned protocol error: {0}")]
    NotificationEndpointError(Oid4vciError<NotificationErrorResponse>),

    #[error("notification endpoint returned unknown protocol error: {0}")]
    NotificationEndpointUnknownError(Oid4vciError<String>),

    #[error("authorization response state mismatch: expected '{expected}', got '{actual}'")]
    AuthorizationResponseStateMismatch { expected: String, actual: String },

    #[error("authorization response issuer mismatch: expected '{expected}', got '{actual}'")]
    AuthorizationResponseIssuerMismatch { expected: String, actual: String },

    #[error("nonce response does not contain a non-empty c_nonce")]
    InvalidNonceResponse,
}

/// Which grant type the orchestrator should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceGrantType {
    AuthorizationCode,
    PreAuthorizedCode,
}

/// Options for resolving an incoming credential offer into a backend context.
#[derive(Debug, Clone, Default)]
pub struct PrepareOfferOptions {
    /// Optional preferred locale used when selecting credential display metadata.
    pub preferred_locale: Option<String>,
    /// Optional explicit grant type selection.
    pub preferred_grant: Option<IssuanceGrantType>,
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
    pub fn grant_type(&self) -> IssuanceGrantType {
        match self {
            Self::AuthorizationCode { .. } => IssuanceGrantType::AuthorizationCode,
            Self::PreAuthorizedCode { .. } => IssuanceGrantType::PreAuthorizedCode,
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

/// Display-oriented credential information derived from issuer metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedCredential {
    pub credential_configuration_id: String,
    pub format: String,
    pub scope: Option<String>,
    pub display: Option<CredentialDisplaySummary>,
}

/// Simplified display metadata for frontend consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDisplaySummary {
    pub name: String,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
    pub logo_uri: Option<Url>,
    pub logo_alt_text: Option<String>,
}

/// Fully resolved context from a single credential offer.
#[derive(Debug, Clone)]
pub struct ResolvedOfferContext {
    pub offer: CredentialOffer,
    pub issuer_metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
    pub authorization_server: Url,
    pub flow: IssuanceFlow,
    pub offered_credentials: Vec<OfferedCredential>,
}

/// How authorization request parameters are conveyed to the AS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizationRequestMode {
    #[default]
    QueryParameters,
    PushedAuthorizationRequest,
}

/// Input for building the authorization redirect URL.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestInput {
    pub client_id: String,
    pub redirect_uri: Option<Url>,
    pub state: String,
    pub scope: Option<String>,
    /// OAuth2 resource indicator; defaults to credential_issuer.
    pub resource: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    pub selected_credential_configuration_ids: Vec<String>,
    /// Extra request parameters (for profile-specific extensions).
    pub additional_parameters: Vec<(String, String)>,
    pub mode: AuthorizationRequestMode,
}

impl AuthorizationRequestInput {
    /// Constructs a minimal authorization request input.
    pub fn new(client_id: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: None,
            state: state.into(),
            scope: None,
            resource: None,
            code_challenge: None,
            code_challenge_method: None,
            selected_credential_configuration_ids: Vec::new(),
            additional_parameters: Vec::new(),
            mode: AuthorizationRequestMode::default(),
        }
    }
}

/// Successful PAR response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedAuthorizationRequestResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

/// Built authorization redirect payload for the frontend/system browser.
#[derive(Debug, Clone)]
pub struct AuthorizationRedirect {
    pub authorization_url: Url,
    pub request: AuthorizationRequest,
    pub pushed_authorization: Option<PushedAuthorizationRequestResponse>,
}

/// Input for exchanging OAuth authorization code for a token.
#[derive(Debug, Clone)]
pub struct AuthorizationCodeExchangeInput {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: Option<Url>,
    pub code_verifier: Option<String>,
    /// OAuth2 resource indicator; defaults to credential_issuer.
    pub resource: Option<String>,
    /// Extra token request parameters.
    pub additional_parameters: Vec<(String, String)>,
    pub selected_credential_configuration_ids: Vec<String>,
}

/// Input for exchanging pre-authorized code for a token.
#[derive(Debug, Clone, Default)]
pub struct PreAuthorizedCodeExchangeInput {
    pub client_id: Option<String>,
    pub tx_code: Option<String>,
    /// OAuth2 resource indicator; defaults to credential_issuer.
    pub resource: Option<String>,
    /// Extra token request parameters.
    pub additional_parameters: Vec<(String, String)>,
    pub selected_credential_configuration_ids: Vec<String>,
}

/// Notification event value for notification endpoint calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialDeleted,
    CredentialFailure,
}

impl NotificationEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::CredentialAccepted => "credential_accepted",
            Self::CredentialDeleted => "credential_deleted",
            Self::CredentialFailure => "credential_failure",
        }
    }
}

/// Parsed authorization callback outcome.
#[derive(Debug)]
pub enum AuthorizationCallback {
    Success(AuthorizationResponse),
    Error(Oid4vciError<AuthzErrorResponse>),
}

/// OID4VCI backend orchestration client.
#[derive(Debug, Clone)]
pub struct Oid4vciClient {
    http_client: reqwest::Client,
}

impl Oid4vciClient {
    /// Creates a new orchestrator with a caller-provided HTTP client.
    pub fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }

    /// Returns the underlying HTTP client.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Resolves raw offer input into a validated `CredentialOffer`.
    pub async fn resolve_credential_offer(
        &self,
        offer_input: &str,
    ) -> Result<CredentialOffer, Oid4vciClientError> {
        self.resolve_offer_input(offer_input).await
    }

    /// Retrieves and validates credential issuer metadata from issuer identifier URL.
    pub async fn resolve_issuer_metadata(
        &self,
        credential_issuer: &Url,
    ) -> Result<CredentialIssuerMetadata, Oid4vciClientError> {
        self.fetch_issuer_metadata(credential_issuer).await
    }

    /// Retrieves and validates authorization server metadata.
    ///
    /// This uses the RFC 8414 primary endpoint and falls back to OpenID Provider
    /// Configuration endpoint when primary endpoint retrieval fails.
    pub async fn resolve_authorization_server_metadata(
        &self,
        authorization_server: &Url,
    ) -> Result<AuthorizationServerMetadata, Oid4vciClientError> {
        self.fetch_authorization_server_metadata(authorization_server)
            .await
    }

    /// Resolves a frontend-provided offer into a backend orchestration context.
    ///
    /// Supported `offer_input` forms:
    /// - Full `openid-credential-offer://` URI
    /// - Query string containing `credential_offer` or `credential_offer_uri`
    /// - Raw credential offer JSON string
    /// - Direct HTTPS credential offer URI
    pub async fn prepare_offer(
        &self,
        offer_input: &str,
    ) -> Result<ResolvedOfferContext, Oid4vciClientError> {
        self.prepare_offer_with_options(offer_input, PrepareOfferOptions::default())
            .await
    }

    /// Resolves a frontend-provided offer into a backend orchestration context.
    ///
    /// Supported `offer_input` forms:
    /// - Full `openid-credential-offer://` URI
    /// - Query string containing `credential_offer` or `credential_offer_uri`
    /// - Raw credential offer JSON string
    /// - Direct HTTPS credential offer URI
    pub async fn prepare_offer_with_options(
        &self,
        offer_input: &str,
        options: PrepareOfferOptions,
    ) -> Result<ResolvedOfferContext, Oid4vciClientError> {
        let offer = self.resolve_offer_input(offer_input).await?;
        let issuer_url = &offer.credential_issuer;

        let issuer_metadata = self.fetch_issuer_metadata(issuer_url).await?;
        if !url_identifier_eq(
            issuer_metadata.credential_issuer.as_str(),
            offer.credential_issuer.as_str(),
        ) {
            return Err(DomainError::message(
                ErrorKind::InvalidIssuerMetadata,
                format!(
                    "issuer metadata credential_issuer '{}' does not match offer credential_issuer '{}'",
                    issuer_metadata.credential_issuer, offer.credential_issuer
                ),
            )
            .into());
        }

        let selected_grant = select_grant_type(&offer, options.preferred_grant)?;
        let requested_authorization_server =
            requested_authorization_server_for_grant(&offer, selected_grant)?;
        let authorization_server = select_authorization_server(
            &issuer_metadata,
            requested_authorization_server.as_deref(),
        )?;

        let authorization_server_metadata = self
            .fetch_authorization_server_metadata(&authorization_server)
            .await?;
        if !url_identifier_eq(
            authorization_server_metadata.issuer.as_str(),
            authorization_server.as_str(),
        ) {
            return Err(DomainError::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                format!(
                    "authorization server metadata issuer '{}' does not match selected authorization server '{}'",
                    authorization_server_metadata.issuer, authorization_server
                ),
            )
            .into());
        }

        let flow = select_flow(&offer, selected_grant)?;
        validate_flow_endpoints(&flow, &authorization_server_metadata)?;

        let offered_credentials = build_offered_credentials(
            &offer,
            &issuer_metadata,
            options.preferred_locale.as_deref(),
        )?;

        Ok(ResolvedOfferContext {
            offer,
            issuer_metadata,
            authorization_server_metadata,
            authorization_server,
            flow,
            offered_credentials,
        })
    }

    /// Builds an authorization redirect URL for authorization code flow.
    pub async fn build_authorization_redirect(
        &self,
        context: &ResolvedOfferContext,
        mut input: AuthorizationRequestInput,
    ) -> Result<AuthorizationRedirect, Oid4vciClientError> {
        if context.flow.grant_type() != IssuanceGrantType::AuthorizationCode {
            return Err(Oid4vciClientError::UnsupportedFlowForOperation);
        }

        if input.code_challenge.is_none() && input.code_challenge_method.is_some() {
            return Err(DomainError::message(
                ErrorKind::InvalidAuthorizationRequest,
                "code_challenge_method requires code_challenge",
            )
            .into());
        }

        if input.code_challenge.is_some() && input.code_challenge_method.is_none() {
            input.code_challenge_method = Some(CodeChallengeMethod::S256);
        }

        let selected_configuration_ids = selected_credential_configuration_ids(
            context,
            &input.selected_credential_configuration_ids,
        )?;
        let authorization_details =
            build_authorization_details(context, &selected_configuration_ids)?;

        let scope = input
            .scope
            .or_else(|| derive_scope_from_selected_configs(context, &selected_configuration_ids));

        let issuer_state = match &context.flow {
            IssuanceFlow::AuthorizationCode { issuer_state } => issuer_state.clone(),
            IssuanceFlow::PreAuthorizedCode { .. } => None,
        };

        let request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: input.client_id.clone(),
            redirect_uri: input.redirect_uri.clone(),
            state: Some(input.state.clone()),
            scope,
            issuer_state,
            authorization_details: Some(authorization_details),
            code_challenge: input.code_challenge.clone(),
            code_challenge_method: input.code_challenge_method,
        };
        let resource = input
            .resource
            .clone()
            .unwrap_or_else(|| context.issuer_metadata.credential_issuer.to_string());

        match input.mode {
            AuthorizationRequestMode::QueryParameters => {
                if context
                    .authorization_server_metadata
                    .require_pushed_authorization_requests
                    .unwrap_or(false)
                {
                    return Err(Oid4vciClientError::PushedAuthorizationRequestRequired);
                }

                let authorization_endpoint = context
                    .authorization_server_metadata
                    .authorization_endpoint
                    .as_ref()
                    .ok_or(Oid4vciClientError::MissingAuthorizationEndpoint)?;
                let authorization_url = build_authorization_url_from_request(
                    authorization_endpoint,
                    &request,
                    &resource,
                    &input.additional_parameters,
                )?;

                Ok(AuthorizationRedirect {
                    authorization_url,
                    request,
                    pushed_authorization: None,
                })
            }
            AuthorizationRequestMode::PushedAuthorizationRequest => {
                let pushed = self
                    .push_authorization_request(
                        context,
                        &request,
                        &input.selected_credential_configuration_ids,
                        &resource,
                        &input.additional_parameters,
                    )
                    .await?;
                let authorization_endpoint = context
                    .authorization_server_metadata
                    .authorization_endpoint
                    .as_ref()
                    .ok_or(Oid4vciClientError::MissingAuthorizationEndpoint)?;

                let mut authorization_url = authorization_endpoint.clone();
                authorization_url
                    .query_pairs_mut()
                    .append_pair("client_id", &request.client_id)
                    .append_pair("request_uri", &pushed.request_uri);

                Ok(AuthorizationRedirect {
                    authorization_url,
                    request,
                    pushed_authorization: Some(pushed),
                })
            }
        }
    }

    /// Parses authorization callback query into success/error result.
    pub fn parse_authorization_callback_query(
        &self,
        query: &str,
    ) -> Result<AuthorizationCallback, Oid4vciClientError> {
        self.parse_and_verify_authorization_callback_query(query, None, None)
    }

    /// Parses and verifies authorization callback query parameters.
    ///
    /// Verification includes:
    /// - optional expected `state`
    /// - optional expected authorization server issuer via `iss` parameter
    pub fn parse_and_verify_authorization_callback_query(
        &self,
        query: &str,
        expected_state: Option<&str>,
        expected_issuer: Option<&Url>,
    ) -> Result<AuthorizationCallback, Oid4vciClientError> {
        let query = query.strip_prefix('?').unwrap_or(query);
        let mut error: Option<String> = None;
        let mut error_description: Option<String> = None;
        let mut iss: Option<String> = None;
        let mut callback_state: Option<String> = None;

        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            if k == "error" {
                error = Some(v.to_string());
            } else if k == "error_description" {
                error_description = Some(v.to_string());
            } else if k == "iss" {
                iss = Some(v.to_string());
            } else if k == "state" {
                callback_state = Some(v.to_string());
            }
        }

        if let Some(expected_state) = expected_state {
            let actual = callback_state.unwrap_or_default();
            if actual != expected_state {
                return Err(Oid4vciClientError::AuthorizationResponseStateMismatch {
                    expected: expected_state.to_string(),
                    actual,
                });
            }
        }

        if let (Some(expected_issuer), Some(actual_iss)) = (expected_issuer, iss.as_deref())
            && !url_identifier_eq(expected_issuer.as_str(), actual_iss)
        {
            return Err(Oid4vciClientError::AuthorizationResponseIssuerMismatch {
                expected: expected_issuer.to_string(),
                actual: actual_iss.to_string(),
            });
        }

        if let Some(error_code) = error {
            let parsed_error = parse_authz_error(&error_code).ok_or_else(|| {
                DomainError::message(
                    ErrorKind::InvalidAuthorizationResponse,
                    format!("unknown authorization error code '{error_code}'"),
                )
            })?;

            return Ok(AuthorizationCallback::Error(Oid4vciError {
                error: parsed_error,
                error_description,
            }));
        }

        let response = AuthorizationResponse::from_query(query)?;
        Ok(AuthorizationCallback::Success(response))
    }

    /// Parses and verifies authorization callback from full redirect URI.
    pub fn parse_and_verify_authorization_callback_redirect_uri(
        &self,
        redirect_uri: &str,
        expected_state: Option<&str>,
        expected_issuer: Option<&Url>,
    ) -> Result<AuthorizationCallback, Oid4vciClientError> {
        let parsed = Url::parse(redirect_uri).map_err(|_| {
            DomainError::message(
                ErrorKind::InvalidAuthorizationResponse,
                format!("'{redirect_uri}' is not a valid URI"),
            )
        })?;
        let query = parsed.query().ok_or_else(|| {
            DomainError::message(
                ErrorKind::InvalidAuthorizationResponse,
                "redirect URI has no query string",
            )
        })?;

        self.parse_and_verify_authorization_callback_query(query, expected_state, expected_issuer)
    }

    /// Exchanges authorization code for an access token.
    pub async fn exchange_authorization_code_token(
        &self,
        context: &ResolvedOfferContext,
        input: AuthorizationCodeExchangeInput,
    ) -> Result<TokenResponse, Oid4vciClientError> {
        if context.flow.grant_type() != IssuanceGrantType::AuthorizationCode {
            return Err(Oid4vciClientError::UnsupportedFlowForOperation);
        }

        let selected_configuration_ids = selected_credential_configuration_ids(
            context,
            &input.selected_credential_configuration_ids,
        )?;
        let authorization_details =
            build_authorization_details(context, &selected_configuration_ids)?;

        let request = TokenRequest::AuthorizationCode(AuthorizationCodeRequest {
            code: input.code,
            redirect_uri: input.redirect_uri,
            client_id: input.client_id,
            code_verifier: input.code_verifier,
            authorization_details: Some(authorization_details),
        });
        let resource = input
            .resource
            .clone()
            .unwrap_or_else(|| context.issuer_metadata.credential_issuer.to_string());
        let mut additional_params = vec![("resource".to_string(), resource)];
        additional_params.extend(input.additional_parameters.clone());

        self.send_token_request(context, &request, &additional_params)
            .await
    }

    /// Exchanges pre-authorized code (and optional tx code) for an access token.
    pub async fn exchange_pre_authorized_code_token(
        &self,
        context: &ResolvedOfferContext,
        input: PreAuthorizedCodeExchangeInput,
    ) -> Result<TokenResponse, Oid4vciClientError> {
        let (pre_authorized_code, tx_spec) = match &context.flow {
            IssuanceFlow::PreAuthorizedCode {
                pre_authorized_code,
                tx_code,
            } => (pre_authorized_code.clone(), tx_code.as_ref()),
            IssuanceFlow::AuthorizationCode { .. } => {
                return Err(Oid4vciClientError::UnsupportedFlowForOperation);
            }
        };

        validate_tx_code(tx_spec, input.tx_code.as_deref())?;
        if !context
            .authorization_server_metadata
            .allows_anonymous_pre_authorized_grant()
            && input.client_id.is_none()
        {
            return Err(Oid4vciClientError::MissingClientIdForPreAuthorizedTokenRequest);
        }

        let selected_configuration_ids = selected_credential_configuration_ids(
            context,
            &input.selected_credential_configuration_ids,
        )?;
        let authorization_details =
            build_authorization_details(context, &selected_configuration_ids)?;

        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code,
            client_id: input.client_id,
            tx_code: input.tx_code,
            authorization_details: Some(authorization_details),
        });
        let resource = input
            .resource
            .clone()
            .unwrap_or_else(|| context.issuer_metadata.credential_issuer.to_string());
        let mut additional_params = vec![("resource".to_string(), resource)];
        additional_params.extend(input.additional_parameters.clone());

        self.send_token_request(context, &request, &additional_params)
            .await
    }

    /// Calls the issuer credential endpoint for a single credential request.
    pub async fn request_credential(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, Oid4vciClientError> {
        request.validate()?;

        let endpoint = context.issuer_metadata.credential_endpoint.clone();
        let endpoint_str = endpoint.to_string();
        let response = self
            .http_client
            .post(endpoint.clone())
            .bearer_auth(access_token)
            .json(request)
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if status.is_success() {
            return parse_json::<CredentialResponse>(&endpoint_str, &body);
        }

        if let Ok(protocol_error) =
            serde_json::from_str::<Oid4vciError<CredentialErrorResponse>>(&body)
        {
            return Err(Oid4vciClientError::CredentialEndpointError(protocol_error));
        }

        if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<String>>(&body) {
            return Err(Oid4vciClientError::CredentialEndpointUnknownError(
                protocol_error,
            ));
        }

        Err(Oid4vciClientError::UnexpectedStatus {
            endpoint: endpoint_str,
            status,
            body,
        })
    }

    /// Calls the issuer credential endpoint for multiple credential requests.
    pub async fn request_credentials(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        requests: &[CredentialRequest],
    ) -> Result<Vec<CredentialResponse>, Oid4vciClientError> {
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            responses.push(
                self.request_credential(context, access_token, request)
                    .await?,
            );
        }
        Ok(responses)
    }

    /// Requests a credential nonce (`c_nonce`) from issuer nonce endpoint.
    pub async fn request_nonce(
        &self,
        context: &ResolvedOfferContext,
    ) -> Result<String, Oid4vciClientError> {
        let endpoint = context
            .issuer_metadata
            .nonce_endpoint
            .as_ref()
            .ok_or(Oid4vciClientError::MissingNonceEndpoint)?;

        #[derive(Debug, Deserialize)]
        struct NonceResponse {
            c_nonce: Option<String>,
        }

        let endpoint = endpoint.clone();
        let endpoint_str = endpoint.to_string();
        let response = self
            .http_client
            .post(endpoint.clone())
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if !status.is_success() {
            return Err(Oid4vciClientError::UnexpectedStatus {
                endpoint: endpoint_str,
                status,
                body,
            });
        }

        let parsed = parse_json::<NonceResponse>(&endpoint_str, &body)?;
        let c_nonce = parsed
            .c_nonce
            .filter(|n| !n.trim().is_empty())
            .ok_or(Oid4vciClientError::InvalidNonceResponse)?;

        Ok(c_nonce)
    }

    /// Sends an issuance notification to notification endpoint.
    pub async fn send_notification(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        notification_id: &str,
        event: NotificationEvent,
        event_description: Option<&str>,
    ) -> Result<(), Oid4vciClientError> {
        let endpoint = context
            .issuer_metadata
            .notification_endpoint
            .as_ref()
            .ok_or(Oid4vciClientError::MissingNotificationEndpoint)?;

        let endpoint = endpoint.clone();
        let endpoint_str = endpoint.to_string();
        let body = serde_json::json!({
            "notification_id": notification_id,
            "event": event.as_str(),
            "event_description": event_description,
        });

        let response = self
            .http_client
            .post(endpoint.clone())
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let response_body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if status == reqwest::StatusCode::NO_CONTENT || status.is_success() {
            return Ok(());
        }

        if let Ok(protocol_error) =
            serde_json::from_str::<Oid4vciError<NotificationErrorResponse>>(&response_body)
        {
            return Err(Oid4vciClientError::NotificationEndpointError(
                protocol_error,
            ));
        }

        if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<String>>(&response_body) {
            return Err(Oid4vciClientError::NotificationEndpointUnknownError(
                protocol_error,
            ));
        }

        Err(Oid4vciClientError::UnexpectedStatus {
            endpoint: endpoint_str,
            status,
            body: response_body,
        })
    }

    /// Polls the deferred credential endpoint for a single transaction id.
    pub async fn poll_deferred_credential(
        &self,
        context: &ResolvedOfferContext,
        access_token: &str,
        transaction_id: &str,
    ) -> Result<DeferredCredentialResult, Oid4vciClientError> {
        let endpoint = context
            .issuer_metadata
            .deferred_credential_endpoint
            .as_ref()
            .ok_or(Oid4vciClientError::MissingDeferredCredentialEndpoint)?;

        let endpoint = endpoint.clone();
        let endpoint_str = endpoint.to_string();
        let body = serde_json::json!({ "transaction_id": transaction_id });
        let response = self
            .http_client
            .post(endpoint.clone())
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if status.is_success() {
            return parse_json::<DeferredCredentialResult>(&endpoint_str, &body);
        }

        if let Ok(protocol_error) =
            serde_json::from_str::<Oid4vciError<DeferredCredentialErrorResponse>>(&body)
        {
            return Err(Oid4vciClientError::DeferredCredentialEndpointError(
                protocol_error,
            ));
        }

        if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<String>>(&body) {
            return Err(Oid4vciClientError::DeferredCredentialEndpointUnknownError(
                protocol_error,
            ));
        }

        Err(Oid4vciClientError::UnexpectedStatus {
            endpoint: endpoint_str,
            status,
            body,
        })
    }

    async fn resolve_offer_input(
        &self,
        offer_input: &str,
    ) -> Result<CredentialOffer, Oid4vciClientError> {
        let trimmed = offer_input.trim();

        if let Ok(parsed_uri) = CredentialOfferUri::from_offer_link(trimmed) {
            return match parsed_uri.source {
                CredentialOfferSource::ByValue(offer) => Ok(offer),
                CredentialOfferSource::ByReference(reference) => {
                    Ok(resolve_by_reference(&reference, &self.http_client).await?)
                }
            };
        }

        if let Ok(url) = Url::parse(trimmed)
            && url.scheme() == "https"
        {
            return Ok(resolve_by_reference(trimmed, &self.http_client).await?);
        }

        Ok(CredentialOffer::from_json_str(trimmed)?)
    }

    async fn fetch_issuer_metadata(
        &self,
        credential_issuer: &Url,
    ) -> Result<CredentialIssuerMetadata, Oid4vciClientError> {
        let endpoint = build_well_known_url(credential_issuer, WELL_KNOWN_OPENID_CREDENTIAL_ISSUER);
        let metadata = self.get_json::<CredentialIssuerMetadata>(&endpoint).await?;
        metadata.validate()?;
        Ok(metadata)
    }

    async fn fetch_authorization_server_metadata(
        &self,
        authorization_server: &Url,
    ) -> Result<AuthorizationServerMetadata, Oid4vciClientError> {
        let primary_endpoint =
            build_well_known_url(authorization_server, WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER);
        match self
            .get_json::<AuthorizationServerMetadata>(&primary_endpoint)
            .await
        {
            Ok(metadata) => {
                metadata.validate()?;
                Ok(metadata)
            }
            Err(Oid4vciClientError::Http { .. } | Oid4vciClientError::UnexpectedStatus { .. }) => {
                let fallback_endpoint = build_openid_configuration_url(
                    authorization_server,
                    WELL_KNOWN_OPENID_CONFIGURATION,
                );
                let metadata = self
                    .get_json::<AuthorizationServerMetadata>(&fallback_endpoint)
                    .await?;
                metadata.validate()?;
                Ok(metadata)
            }
            Err(other) => Err(other),
        }
    }

    async fn get_json<T: DeserializeOwned>(&self, endpoint: &Url) -> Result<T, Oid4vciClientError> {
        let endpoint_str = endpoint.to_string();
        let response = self
            .http_client
            .get(endpoint.clone())
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if !status.is_success() {
            return Err(Oid4vciClientError::UnexpectedStatus {
                endpoint: endpoint_str,
                status,
                body,
            });
        }

        parse_json(endpoint.as_str(), &body)
    }

    async fn push_authorization_request(
        &self,
        context: &ResolvedOfferContext,
        request: &AuthorizationRequest,
        selected_credential_configuration_ids: &[String],
        resource: &str,
        additional_parameters: &[(String, String)],
    ) -> Result<PushedAuthorizationRequestResponse, Oid4vciClientError> {
        let endpoint = context
            .authorization_server_metadata
            .pushed_authorization_request_endpoint
            .as_ref()
            .ok_or(Oid4vciClientError::MissingPushedAuthorizationRequestEndpoint)?;

        let endpoint = endpoint.clone();
        let endpoint_str = endpoint.to_string();
        let mut form = authorization_request_to_form_pairs(request)?;
        if request.authorization_details.is_none()
            && !selected_credential_configuration_ids.is_empty()
        {
            form.push((
                "authorization_details".to_string(),
                serde_json::to_string(selected_credential_configuration_ids).map_err(|e| {
                    Oid4vciClientError::InvalidJson {
                        endpoint: endpoint_str.clone(),
                        source: e,
                    }
                })?,
            ));
        }
        form.push(("resource".to_string(), resource.to_string()));
        form.extend(additional_parameters.iter().cloned());

        let encoded_form = encode_form_pairs(&form);
        let response = self
            .http_client
            .post(endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encoded_form)
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if !status.is_success() {
            if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<String>>(&body) {
                return Err(Oid4vciClientError::PushedAuthorizationRequestEndpointError(
                    protocol_error,
                ));
            }

            return Err(Oid4vciClientError::UnexpectedStatus {
                endpoint: endpoint_str,
                status,
                body,
            });
        }

        #[derive(Debug, Deserialize)]
        struct ParResponse {
            request_uri: String,
            expires_in: u64,
        }

        let parsed = parse_json::<ParResponse>(&endpoint_str, &body)?;
        Ok(PushedAuthorizationRequestResponse {
            request_uri: parsed.request_uri,
            expires_in: parsed.expires_in,
        })
    }

    async fn send_token_request(
        &self,
        context: &ResolvedOfferContext,
        request: &TokenRequest,
        additional_parameters: &[(String, String)],
    ) -> Result<TokenResponse, Oid4vciClientError> {
        let token_endpoint = context
            .authorization_server_metadata
            .token_endpoint
            .as_ref()
            .ok_or(Oid4vciClientError::MissingTokenEndpoint)?;

        let token_endpoint = token_endpoint.clone();
        let endpoint_str = token_endpoint.to_string();
        let form = token_request_to_form_pairs(request, additional_parameters)?;
        let encoded_form = encode_form_pairs(&form);
        let response = self
            .http_client
            .post(token_endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encoded_form)
            .send()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| Oid4vciClientError::Http {
                endpoint: endpoint_str.clone(),
                source,
            })?;

        if status.is_success() {
            let parsed = parse_json::<TokenResponse>(&endpoint_str, &body)?;
            validate_token_response(&parsed)?;
            return Ok(parsed);
        }

        if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<TokenErrorResponse>>(&body)
        {
            return Err(Oid4vciClientError::TokenEndpointError(protocol_error));
        }

        if let Ok(protocol_error) = serde_json::from_str::<Oid4vciError<String>>(&body) {
            return Err(Oid4vciClientError::TokenEndpointUnknownError(
                protocol_error,
            ));
        }

        Err(Oid4vciClientError::UnexpectedStatus {
            endpoint: endpoint_str,
            status,
            body,
        })
    }
}

fn build_well_known_url(issuer: &Url, well_known_name: &str) -> Url {
    let path = issuer.path().trim_matches('/');
    let well_known_path = if path.is_empty() {
        format!("/.well-known/{well_known_name}")
    } else {
        format!("/.well-known/{well_known_name}/{path}")
    };

    let mut url = issuer.clone();
    url.set_path(&well_known_path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn build_openid_configuration_url(issuer: &Url, well_known_name: &str) -> Url {
    let path = issuer.path().trim_end_matches('/');
    let openid_configuration_path = if path.is_empty() {
        format!("/.well-known/{well_known_name}")
    } else {
        format!("{path}/.well-known/{well_known_name}")
    };

    let mut url = issuer.clone();
    url.set_path(&openid_configuration_path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn parse_json<T: DeserializeOwned>(endpoint: &str, body: &str) -> Result<T, Oid4vciClientError> {
    serde_json::from_str(body).map_err(|source| Oid4vciClientError::InvalidJson {
        endpoint: endpoint.to_string(),
        source,
    })
}

fn validate_token_response(token_response: &TokenResponse) -> Result<(), Oid4vciClientError> {
    if token_response.access_token.trim().is_empty() {
        return Err(DomainError::message(
            ErrorKind::InvalidTokenResponse,
            "token response access_token must not be empty",
        )
        .into());
    }

    if token_response.token_type.trim().is_empty() {
        return Err(DomainError::message(
            ErrorKind::InvalidTokenResponse,
            "token response token_type must not be empty",
        )
        .into());
    }

    Ok(())
}

fn select_grant_type(
    offer: &CredentialOffer,
    preferred_grant: Option<IssuanceGrantType>,
) -> Result<IssuanceGrantType, Oid4vciClientError> {
    let has_pre_authorized_code = offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.as_ref())
        .is_some();
    let has_authorization_code = offer
        .grants
        .as_ref()
        .and_then(|g| g.authorization_code.as_ref())
        .is_some();

    let selected = match preferred_grant {
        Some(IssuanceGrantType::PreAuthorizedCode) if has_pre_authorized_code => {
            IssuanceGrantType::PreAuthorizedCode
        }
        Some(IssuanceGrantType::AuthorizationCode) if has_authorization_code => {
            IssuanceGrantType::AuthorizationCode
        }
        Some(IssuanceGrantType::AuthorizationCode)
            if !has_pre_authorized_code && !has_authorization_code =>
        {
            IssuanceGrantType::AuthorizationCode
        }
        Some(_) => {
            return Err(DomainError::message(
                ErrorKind::InvalidCredentialOffer,
                "preferred grant is not supported by this offer",
            )
            .into());
        }
        None if has_pre_authorized_code => IssuanceGrantType::PreAuthorizedCode,
        None if has_authorization_code => IssuanceGrantType::AuthorizationCode,
        None => IssuanceGrantType::AuthorizationCode,
    };

    Ok(selected)
}

fn select_flow(
    offer: &CredentialOffer,
    grant: IssuanceGrantType,
) -> Result<IssuanceFlow, Oid4vciClientError> {
    match grant {
        IssuanceGrantType::AuthorizationCode => {
            let issuer_state = offer
                .grants
                .as_ref()
                .and_then(|g| g.authorization_code.as_ref())
                .and_then(|g| g.issuer_state.clone());
            Ok(IssuanceFlow::AuthorizationCode { issuer_state })
        }
        IssuanceGrantType::PreAuthorizedCode => {
            let pre_auth_grant = offer
                .grants
                .as_ref()
                .and_then(|g| g.pre_authorized_code.as_ref())
                .ok_or(Oid4vciClientError::MissingGrantData)?;

            Ok(IssuanceFlow::PreAuthorizedCode {
                pre_authorized_code: pre_auth_grant.pre_authorized_code.clone(),
                tx_code: pre_auth_grant.tx_code.clone(),
            })
        }
    }
}

fn requested_authorization_server_for_grant(
    offer: &CredentialOffer,
    grant: IssuanceGrantType,
) -> Result<Option<String>, Oid4vciClientError> {
    match grant {
        IssuanceGrantType::AuthorizationCode => Ok(offer
            .grants
            .as_ref()
            .and_then(|g| g.authorization_code.as_ref())
            .and_then(|g| g.authorization_server.clone())),
        IssuanceGrantType::PreAuthorizedCode => Ok(offer
            .grants
            .as_ref()
            .and_then(|g| g.pre_authorized_code.as_ref())
            .ok_or(Oid4vciClientError::MissingGrantData)?
            .authorization_server
            .clone()),
    }
}

fn select_authorization_server(
    issuer_metadata: &CredentialIssuerMetadata,
    requested_authorization_server: Option<&str>,
) -> Result<Url, Oid4vciClientError> {
    if let Some(authorization_servers) = &issuer_metadata.authorization_servers {
        if authorization_servers.is_empty() {
            return Err(DomainError::message(
                ErrorKind::InvalidIssuerMetadata,
                "authorization_servers must not be an empty array when present",
            )
            .into());
        }

        if let Some(requested) = requested_authorization_server {
            if let Some(found) = authorization_servers
                .iter()
                .find(|candidate| url_identifier_eq(candidate.as_str(), requested))
            {
                return Ok(found.clone());
            }

            return Err(Oid4vciClientError::UnknownAuthorizationServer {
                requested: requested.to_string(),
            });
        }

        if authorization_servers.len() > 1 {
            return Err(Oid4vciClientError::AmbiguousAuthorizationServer);
        }

        return Ok(authorization_servers[0].clone());
    }

    Ok(issuer_metadata.credential_issuer.clone())
}

fn validate_flow_endpoints(
    flow: &IssuanceFlow,
    metadata: &AuthorizationServerMetadata,
) -> Result<(), Oid4vciClientError> {
    if metadata.token_endpoint.is_none() {
        return Err(Oid4vciClientError::MissingTokenEndpoint);
    }

    if matches!(flow, IssuanceFlow::AuthorizationCode { .. })
        && metadata.authorization_endpoint.is_none()
    {
        return Err(Oid4vciClientError::MissingAuthorizationEndpoint);
    }

    Ok(())
}

fn build_offered_credentials(
    offer: &CredentialOffer,
    issuer_metadata: &CredentialIssuerMetadata,
    preferred_locale: Option<&str>,
) -> Result<Vec<OfferedCredential>, Oid4vciClientError> {
    offer
        .credential_configuration_ids
        .iter()
        .map(|configuration_id| {
            let configuration = issuer_metadata
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or_else(|| Oid4vciClientError::UnknownCredentialConfigurationId {
                    id: configuration_id.clone(),
                })?;

            Ok(OfferedCredential {
                credential_configuration_id: configuration_id.clone(),
                format: configuration.format_details.format_str().to_string(),
                scope: configuration.scope.clone(),
                display: select_credential_display_summary(configuration, preferred_locale),
            })
        })
        .collect()
}

fn select_credential_display_summary(
    configuration: &CredentialConfiguration,
    preferred_locale: Option<&str>,
) -> Option<CredentialDisplaySummary> {
    let displays = configuration
        .credential_metadata
        .as_ref()?
        .display
        .as_ref()?;
    let selected = select_display_for_locale(displays, preferred_locale)?;

    Some(CredentialDisplaySummary {
        name: selected.name.clone(),
        description: selected.description.clone(),
        background_color: selected.background_color.as_ref().map(ToString::to_string),
        text_color: selected.text_color.as_ref().map(ToString::to_string),
        logo_uri: selected.logo.as_ref().map(|logo| logo.uri.clone()),
        logo_alt_text: selected
            .logo
            .as_ref()
            .and_then(|logo| logo.alt_text.clone()),
    })
}

fn select_display_for_locale<'a>(
    displays: &'a [CredentialDisplay],
    preferred_locale: Option<&str>,
) -> Option<&'a CredentialDisplay> {
    if displays.is_empty() {
        return None;
    }

    let Some(preferred_locale) = preferred_locale else {
        return displays.first();
    };

    let preferred_locale = preferred_locale.to_ascii_lowercase();

    if let Some(exact_match) = displays.iter().find(|entry| {
        entry
            .locale
            .as_deref()
            .is_some_and(|locale| locale.eq_ignore_ascii_case(&preferred_locale))
    }) {
        return Some(exact_match);
    }

    let preferred_primary = preferred_locale.split('-').next().unwrap_or("");
    if !preferred_primary.is_empty()
        && let Some(primary_match) = displays.iter().find(|entry| {
            entry.locale.as_deref().is_some_and(|locale| {
                locale
                    .split('-')
                    .next()
                    .is_some_and(|primary| primary.eq_ignore_ascii_case(preferred_primary))
            })
        })
    {
        return Some(primary_match);
    }

    displays.first()
}

fn selected_credential_configuration_ids(
    context: &ResolvedOfferContext,
    selected_configuration_ids: &[String],
) -> Result<Vec<String>, Oid4vciClientError> {
    let ids = if selected_configuration_ids.is_empty() {
        context.offer.credential_configuration_ids.clone()
    } else {
        selected_configuration_ids.to_vec()
    };

    let offered: HashSet<&str> = context
        .offer
        .credential_configuration_ids
        .iter()
        .map(String::as_str)
        .collect();

    let mut deduplicated = Vec::with_capacity(ids.len());
    let mut seen = HashSet::<String>::new();
    for id in ids {
        if !offered.contains(id.as_str()) {
            return Err(Oid4vciClientError::UnknownCredentialConfigurationId { id });
        }
        if seen.insert(id.clone()) {
            deduplicated.push(id);
        }
    }

    Ok(deduplicated)
}

fn derive_scope_from_selected_configs(
    context: &ResolvedOfferContext,
    selected_configuration_ids: &[String],
) -> Option<String> {
    let mut scopes = Vec::<String>::new();
    let mut seen = HashSet::<&str>::new();

    for id in selected_configuration_ids {
        let scope = context
            .issuer_metadata
            .credential_configurations_supported
            .get(id)
            .and_then(|config| config.scope.as_deref());

        if let Some(scope) = scope
            && seen.insert(scope)
        {
            scopes.push(scope.to_string());
        }
    }

    if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    }
}

fn build_authorization_details(
    context: &ResolvedOfferContext,
    selected_configuration_ids: &[String],
) -> Result<Vec<AuthorizationDetails>, Oid4vciClientError> {
    let include_locations = context.issuer_metadata.authorization_servers.is_some();

    selected_configuration_ids
        .iter()
        .map(|id| {
            if !context
                .issuer_metadata
                .credential_configurations_supported
                .contains_key(id)
            {
                return Err(Oid4vciClientError::UnknownCredentialConfigurationId {
                    id: id.clone(),
                });
            }

            let detail = if include_locations {
                AuthorizationDetails::for_configuration(id.clone())
                    .with_locations(vec![context.issuer_metadata.credential_issuer.clone()])
            } else {
                AuthorizationDetails::for_configuration(id.clone())
            };

            Ok(detail)
        })
        .collect()
}

fn authorization_request_to_form_pairs(
    request: &AuthorizationRequest,
) -> Result<Vec<(String, String)>, Oid4vciClientError> {
    let mut pairs = vec![
        ("response_type".to_string(), request.response_type.clone()),
        ("client_id".to_string(), request.client_id.clone()),
    ];

    if let Some(redirect_uri) = &request.redirect_uri {
        pairs.push(("redirect_uri".to_string(), redirect_uri.to_string()));
    }

    if let Some(state) = &request.state {
        pairs.push(("state".to_string(), state.clone()));
    }

    if let Some(scope) = &request.scope {
        pairs.push(("scope".to_string(), scope.clone()));
    }

    if let Some(issuer_state) = &request.issuer_state {
        pairs.push(("issuer_state".to_string(), issuer_state.clone()));
    }

    if let Some(authorization_details) = &request.authorization_details {
        pairs.push((
            "authorization_details".to_string(),
            serde_json::to_string(authorization_details).map_err(|source| {
                Oid4vciClientError::InvalidJson {
                    endpoint: "authorization_request".to_string(),
                    source,
                }
            })?,
        ));
    }

    if let Some(code_challenge) = &request.code_challenge {
        pairs.push(("code_challenge".to_string(), code_challenge.clone()));
    }

    if let Some(code_challenge_method) = request.code_challenge_method {
        pairs.push((
            "code_challenge_method".to_string(),
            code_challenge_method.to_string(),
        ));
    }

    Ok(pairs)
}

fn build_authorization_url_from_request(
    authorization_endpoint: &Url,
    request: &AuthorizationRequest,
    resource: &str,
    additional_parameters: &[(String, String)],
) -> Result<Url, Oid4vciClientError> {
    let mut url = authorization_endpoint.clone();
    let pairs = authorization_request_to_form_pairs(request)?;
    {
        let mut query = url.query_pairs_mut();
        for (k, v) in pairs {
            query.append_pair(&k, &v);
        }
        query.append_pair("resource", resource);
        for (k, v) in additional_parameters {
            query.append_pair(k, v);
        }
    }
    Ok(url)
}

fn token_request_to_form_pairs(
    request: &TokenRequest,
    additional_parameters: &[(String, String)],
) -> Result<Vec<(String, String)>, Oid4vciClientError> {
    let mut pairs = match request {
        TokenRequest::AuthorizationCode(payload) => {
            let mut pairs = vec![
                ("grant_type".to_string(), "authorization_code".to_string()),
                ("code".to_string(), payload.code.clone()),
                ("client_id".to_string(), payload.client_id.clone()),
            ];

            if let Some(redirect_uri) = &payload.redirect_uri {
                pairs.push(("redirect_uri".to_string(), redirect_uri.to_string()));
            }

            if let Some(code_verifier) = &payload.code_verifier {
                pairs.push(("code_verifier".to_string(), code_verifier.clone()));
            }

            if let Some(authorization_details) = &payload.authorization_details {
                pairs.push((
                    "authorization_details".to_string(),
                    serde_json::to_string(authorization_details).map_err(|source| {
                        Oid4vciClientError::InvalidJson {
                            endpoint: "token_request".to_string(),
                            source,
                        }
                    })?,
                ));
            }

            pairs
        }
        TokenRequest::PreAuthorizedCode(payload) => {
            let mut pairs = vec![
                (
                    "grant_type".to_string(),
                    PRE_AUTHORIZED_CODE_GRANT_TYPE.to_string(),
                ),
                (
                    "pre-authorized_code".to_string(),
                    payload.pre_authorized_code.clone(),
                ),
            ];
            if let Some(client_id) = &payload.client_id {
                pairs.push(("client_id".to_string(), client_id.clone()));
            }

            if let Some(tx_code) = &payload.tx_code {
                pairs.push(("tx_code".to_string(), tx_code.clone()));
            }

            if let Some(authorization_details) = &payload.authorization_details {
                pairs.push((
                    "authorization_details".to_string(),
                    serde_json::to_string(authorization_details).map_err(|source| {
                        Oid4vciClientError::InvalidJson {
                            endpoint: "token_request".to_string(),
                            source,
                        }
                    })?,
                ));
            }

            pairs
        }
    };

    pairs.extend(additional_parameters.iter().cloned());
    Ok(pairs)
}

fn parse_authz_error(error_code: &str) -> Option<AuthzErrorResponse> {
    match error_code {
        "invalid_request" => Some(AuthzErrorResponse::InvalidRequest),
        "unauthorized_client" => Some(AuthzErrorResponse::UnauthorizedClient),
        "access_denied" => Some(AuthzErrorResponse::AccessDenied),
        "unsupported_response_type" => Some(AuthzErrorResponse::UnsupportedResponseType),
        "invalid_scope" => Some(AuthzErrorResponse::InvalidScope),
        "server_error" => Some(AuthzErrorResponse::ServerError),
        "temporarily_unavailable" => Some(AuthzErrorResponse::TemporarilyUnavailable),
        _ => None,
    }
}

fn validate_tx_code(
    tx_spec: Option<&TxCode>,
    tx_code: Option<&str>,
) -> Result<(), Oid4vciClientError> {
    let Some(tx_spec) = tx_spec else {
        return Ok(());
    };

    let tx_code = tx_code.ok_or(Oid4vciClientError::MissingTxCode)?;

    let input_mode = tx_spec.input_mode.unwrap_or(InputMode::Numeric);
    if matches!(input_mode, InputMode::Numeric) && !tx_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(Oid4vciClientError::InvalidTxCodeFormat);
    }

    if let Some(expected_length) = tx_spec.length
        && tx_code.len() != expected_length as usize
    {
        return Err(Oid4vciClientError::InvalidTxCodeLength {
            expected: expected_length,
        });
    }

    Ok(())
}

fn encode_form_pairs(pairs: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn url_identifier_eq(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }

    let left = left.strip_suffix('/').unwrap_or(left);
    let right = right.strip_suffix('/').unwrap_or(right);
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_offer() -> CredentialOffer {
        CredentialOffer::from_json_str(
            r#"{
                "credential_issuer":"https://issuer.example.com",
                "credential_configuration_ids":["UniversityDegreeCredential","EmployeeIDCredential"],
                "grants":{
                    "authorization_code":{"issuer_state":"issuer-state"},
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                        "pre-authorized_code":"pre-auth-code",
                        "tx_code":{"input_mode":"numeric","length":6}
                    }
                }
            }"#,
        )
        .expect("valid offer")
    }

    fn sample_issuer_metadata() -> CredentialIssuerMetadata {
        serde_json::from_value(json!({
            "credential_issuer":"https://issuer.example.com",
            "authorization_servers":["https://as.example.com"],
            "credential_endpoint":"https://issuer.example.com/credential",
            "deferred_credential_endpoint":"https://issuer.example.com/deferred",
            "credential_configurations_supported":{
                "UniversityDegreeCredential":{
                    "format":"dc+sd-jwt",
                    "vct":"https://example.com/vct/degree",
                    "scope":"degree",
                    "credential_metadata":{
                        "display":[
                            {
                                "name":"University Degree",
                                "locale":"en-US",
                                "description":"Degree credential",
                                "background_color":"#112233",
                                "text_color":"#ffffff",
                                "logo":{"uri":"https://issuer.example.com/logo-degree.png","alt_text":"Degree logo"}
                            },
                            {
                                "name":"Diplome universitaire",
                                "locale":"fr-FR",
                                "description":"Diplome"
                            }
                        ]
                    }
                },
                "EmployeeIDCredential":{
                    "format":"dc+sd-jwt",
                    "vct":"https://example.com/vct/employee",
                    "scope":"employee"
                }
            }
        }))
        .expect("valid metadata")
    }

    fn sample_as_metadata() -> AuthorizationServerMetadata {
        serde_json::from_value(json!({
            "issuer":"https://as.example.com",
            "authorization_endpoint":"https://as.example.com/authorize",
            "token_endpoint":"https://as.example.com/token",
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code","urn:ietf:params:oauth:grant-type:pre-authorized_code"],
            "pushed_authorization_request_endpoint":"https://as.example.com/par",
            "require_pushed_authorization_requests":false
        }))
        .expect("valid as metadata")
    }

    fn sample_context(flow: IssuanceFlow) -> ResolvedOfferContext {
        let offer = sample_offer();
        let issuer_metadata = sample_issuer_metadata();
        let authorization_server_metadata = sample_as_metadata();

        let offered_credentials =
            build_offered_credentials(&offer, &issuer_metadata, Some("en-US")).unwrap();
        ResolvedOfferContext {
            offer,
            issuer_metadata,
            authorization_server_metadata,
            authorization_server: Url::parse("https://as.example.com").unwrap(),
            flow,
            offered_credentials,
        }
    }

    #[test]
    fn select_grant_defaults_to_pre_authorized_when_present() {
        let offer = sample_offer();
        let selected = select_grant_type(&offer, None).unwrap();
        assert_eq!(selected, IssuanceGrantType::PreAuthorizedCode);
    }

    #[test]
    fn select_grant_uses_preference_when_supported() {
        let offer = sample_offer();
        let selected =
            select_grant_type(&offer, Some(IssuanceGrantType::AuthorizationCode)).unwrap();
        assert_eq!(selected, IssuanceGrantType::AuthorizationCode);
    }

    #[test]
    fn validate_tx_code_accepts_matching_numeric_code() {
        let tx = TxCode {
            input_mode: Some(InputMode::Numeric),
            length: Some(6),
            description: None,
        };
        assert!(validate_tx_code(Some(&tx), Some("123456")).is_ok());
    }

    #[test]
    fn validate_tx_code_rejects_non_digit_when_numeric() {
        let tx = TxCode {
            input_mode: Some(InputMode::Numeric),
            length: None,
            description: None,
        };
        assert!(matches!(
            validate_tx_code(Some(&tx), Some("12AB56")),
            Err(Oid4vciClientError::InvalidTxCodeFormat)
        ));
    }

    #[test]
    fn validate_tx_code_rejects_wrong_length() {
        let tx = TxCode {
            input_mode: Some(InputMode::Text),
            length: Some(4),
            description: None,
        };
        assert!(matches!(
            validate_tx_code(Some(&tx), Some("12345")),
            Err(Oid4vciClientError::InvalidTxCodeLength { expected: 4 })
        ));
    }

    #[test]
    fn build_openid_configuration_url_uses_appended_path() {
        let issuer = Url::parse("https://issuer.example.com/some/path").unwrap();
        let url = build_openid_configuration_url(&issuer, WELL_KNOWN_OPENID_CONFIGURATION);
        assert_eq!(
            url.as_str(),
            "https://issuer.example.com/some/path/.well-known/openid-configuration"
        );
    }

    #[test]
    fn parse_and_verify_callback_rejects_state_mismatch() {
        let client = Oid4vciClient::new(reqwest::Client::new());
        let err = client
            .parse_and_verify_authorization_callback_query(
                "code=abc&state=actual",
                Some("expected"),
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            Oid4vciClientError::AuthorizationResponseStateMismatch { .. }
        ));
    }

    #[test]
    fn parse_and_verify_callback_rejects_issuer_mismatch() {
        let client = Oid4vciClient::new(reqwest::Client::new());
        let err = client
            .parse_and_verify_authorization_callback_query(
                "code=abc&state=s&iss=https%3A%2F%2Fevil.example.com",
                Some("s"),
                Some(&Url::parse("https://as.example.com").unwrap()),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            Oid4vciClientError::AuthorizationResponseIssuerMismatch { .. }
        ));
    }

    #[test]
    fn token_request_pairs_include_client_id_for_pre_authorized_request() {
        let request = TokenRequest::PreAuthorizedCode(PreAuthorizedCodeRequest {
            pre_authorized_code: "pre-auth".to_string(),
            client_id: Some("wallet-client".to_string()),
            tx_code: None,
            authorization_details: None,
        });

        let form =
            token_request_to_form_pairs(&request, &[("resource".to_string(), "r".to_string())])
                .expect("form pairs");
        let form_map: std::collections::HashMap<_, _> = form.into_iter().collect();
        assert_eq!(
            form_map.get("client_id").map(String::as_str),
            Some("wallet-client")
        );
        assert_eq!(form_map.get("resource").map(String::as_str), Some("r"));
    }

    #[test]
    fn offered_credentials_use_locale_fallback_matching() {
        let offer = sample_offer();
        let issuer_metadata = sample_issuer_metadata();
        let offered = build_offered_credentials(&offer, &issuer_metadata, Some("fr-CA")).unwrap();

        assert_eq!(offered.len(), 2);
        let first = &offered[0];
        let display = first.display.as_ref().unwrap();
        assert_eq!(display.name, "Diplome universitaire");
    }

    #[tokio::test]
    async fn build_authorization_redirect_contains_expected_params() {
        let context = sample_context(IssuanceFlow::AuthorizationCode {
            issuer_state: Some("issuer-state".to_string()),
        });
        let client = Oid4vciClient::new(reqwest::Client::new());
        let mut input = AuthorizationRequestInput::new("wallet-client", "session-state");
        input.redirect_uri = Some(Url::parse("https://wallet.example.com/callback").unwrap());
        input.code_challenge = Some("pkce-challenge".to_string());
        input.selected_credential_configuration_ids =
            vec!["UniversityDegreeCredential".to_string()];

        let redirect = client
            .build_authorization_redirect(&context, input)
            .await
            .expect("authorization redirect");

        let params: std::collections::HashMap<_, _> = redirect
            .authorization_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        assert_eq!(
            params.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            params.get("client_id").map(String::as_str),
            Some("wallet-client")
        );
        assert_eq!(
            params.get("state").map(String::as_str),
            Some("session-state")
        );
        assert_eq!(
            params.get("issuer_state").map(String::as_str),
            Some("issuer-state")
        );
        assert_eq!(
            params.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(params.contains_key("authorization_details"));
    }
}
