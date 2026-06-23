use cloud_wallet_openid4vc::oid4vci::client::ResolvedOfferContext;
use cloud_wallet_openid4vc::oid4vp::client::PresentationContext;
use cloud_wallet_openid4vc::oid4vp::selection::SelectionResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::models::issuance::FlowType;
use crate::session::Result;
use crate::session::SessionError;
use crate::session::utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceState,
    pub context: ResolvedOfferContext,
    /// Selected configuration IDs for issuance.
    /// Empty by default, should be overridden
    /// after user consent.
    pub selected_config_ids: Vec<String>,
    pub flow: FlowType,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    AwaitingConsent,
    AwaitingAuthorization,
    AwaitingTxCode,
    Processing,
    Completed,
    Failed,
}

impl IssuanceState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

impl IssuanceSession {
    pub fn new(tenant_id: Uuid, context: ResolvedOfferContext, flow: FlowType) -> Self {
        Self {
            id: utils::generate_session_id(),
            tenant_id,
            state: IssuanceState::AwaitingConsent,
            context,
            selected_config_ids: vec![],
            flow,
            code_verifier: None,
        }
    }
}

pub fn transition(session: &mut IssuanceSession, new_state: IssuanceState) -> Result<()> {
    let allowed = is_transition_allowed(session.state, new_state, session.flow);
    if !allowed {
        return Err(SessionError::InvalidStateTransition(
            format!("{:?}", session.state).into(),
            format!("{:?}", new_state).into(),
        ));
    }
    session.state = new_state;
    Ok(())
}

fn is_transition_allowed(from: IssuanceState, to: IssuanceState, flow: FlowType) -> bool {
    use FlowType::*;
    use IssuanceState::*;
    match (from, to) {
        // awaiting_consent -> awaiting_authorization (Consent accepted, authorization code flow)
        (AwaitingConsent, AwaitingAuthorization) if flow == AuthorizationCode => true,
        // awaiting_consent -> awaiting_tx_code (Consent accepted, pre-auth flow, tx_code required)
        (AwaitingConsent, AwaitingTxCode) if flow == PreAuthorizedCode => true,
        // awaiting_consent -> processing (Consent accepted, pre-auth flow, no tx_code)
        (AwaitingConsent, Processing) if flow == PreAuthorizedCode => true,
        // awaiting_authorization -> processing (Authorization callback received with valid code)
        (AwaitingAuthorization, Processing) if flow == AuthorizationCode => true,
        // awaiting_tx_code -> processing (tx_code submitted)
        (AwaitingTxCode, Processing) if flow == PreAuthorizedCode => true,
        // processing -> completed (Credential stored successfully)
        (Processing, Completed) => true,
        // Any non-terminal -> failed (POST /cancel or session expiry)
        (from, Failed) if !from.is_terminal() => true,

        _ => false,
    }
}

/// A server-side session bridging POST /start and POST /consent for the
/// presentation flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSession {
    /// Presentation session ID (starts with `prs_`).
    pub id: String,
    /// The tenant this session belongs to.
    pub tenant_id: Uuid,
    /// Current state of the presentation session.
    pub state: PresentationState,
    /// The fully validated presentation context produced by
    /// [`Oid4vpClient::process_authz_request`].
    pub context: PresentationContext,
    /// The DCQL evaluation result: which wallet credentials match which
    /// credential queries, with requested claim paths.
    pub dcql_result: SelectionResult,
    /// The `flow` field returned to the frontend (`cross_device` or
    /// `same_device`), derived from `response_mode` in the context.
    pub flow: PresentationFlow,
}

/// States of a presentation session.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresentationState {
    /// Created by `/start`. Waiting for user consent.
    AwaitingConsent,
    /// Terminal. Set by `/consent` on success or rejection.
    Completed,
    /// Terminal. Set by `/consent` on error.
    Failed,
}

impl PresentationState {
    /// Returns `true` if the state is terminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// The presentation flow type, derived from the authorization request's
/// `response_mode`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresentationFlow {
    CrossDevice,
    SameDevice,
}

impl From<&cloud_wallet_openid4vc::oid4vp::authorization::ResponseMode> for PresentationFlow {
    fn from(mode: &cloud_wallet_openid4vc::oid4vp::authorization::ResponseMode) -> Self {
        use cloud_wallet_openid4vc::oid4vp::authorization::ResponseMode;
        match mode {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => Self::CrossDevice,
            ResponseMode::DcApi | ResponseMode::DcApiJwt => Self::SameDevice,
            ResponseMode::Other(s) if s == "fragment" => Self::SameDevice,
            ResponseMode::Other(_) => Self::CrossDevice, // Extension modes default to cross-device
        }
    }
}

impl PresentationSession {
    /// Creates a new presentation session in `AwaitingConsent` state.
    ///
    /// The `flow` is derived automatically from the `response_mode` field of
    /// the presentation context. The context is moved into the session (no clone).
    pub fn new(
        tenant_id: Uuid,
        context: PresentationContext,
        dcql_result: SelectionResult,
    ) -> Self {
        let flow = PresentationFlow::from(&context.response_mode);
        Self {
            id: utils::generate_presentation_session_id(),
            tenant_id,
            state: PresentationState::AwaitingConsent,
            context,
            dcql_result,
            flow,
        }
    }
}

/// Validates and applies a state transition for a [`PresentationSession`].
///
/// Only `AwaitingConsent -> Completed` and `AwaitingConsent -> Failed` are
/// allowed. Any other transition returns [`SessionError::InvalidStateTransition`].
pub fn transition_presentation_session(
    session: &mut PresentationSession,
    new_state: PresentationState,
) -> Result<()> {
    if session.state != PresentationState::AwaitingConsent {
        return Err(SessionError::InvalidStateTransition(
            format!("{:?}", session.state).into(),
            format!("{:?}", new_state).into(),
        ));
    }
    if !new_state.is_terminal() {
        return Err(SessionError::InvalidStateTransition(
            format!("{:?}", session.state).into(),
            format!("{:?}", new_state).into(),
        ));
    }
    session.state = new_state;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_openid4vc::oid4vp::authorization::{AuthorizationRequest, ResponseMode};

    fn mock_session(flow: FlowType) -> IssuanceSession {
        let context = serde_json::from_value(serde_json::json!({
            "offer": {
                "credential_issuer": "https://issuer.example.com",
                "credential_configuration_ids": ["test_id"],
                "grants": {
                    "authorization_code": {
                        "issuer_state": "test_state"
                    }
                }
            },
            "issuer_metadata": {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "credential_configurations_supported": {
                    "test_id": {
                        "format": "dc+sd-jwt",
                        "vct": "https://credentials.example.com/test"
                    }
                }
            },
            "as_metadata": {
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "response_types_supported": ["code"]
            },
            "flow": {
                "AuthorizationCode": {
                    "issuer_state": "test_state"
                }
            },
        }))
        .unwrap();

        IssuanceSession::new(Uuid::new_v4(), context, flow)
    }

    #[test]
    fn test_auth_code_flow_transitions() {
        let mut session = mock_session(FlowType::AuthorizationCode);
        assert_eq!(session.state, IssuanceState::AwaitingConsent);

        // Valid transitions
        transition(&mut session, IssuanceState::AwaitingAuthorization).unwrap();
        transition(&mut session, IssuanceState::Processing).unwrap();
        transition(&mut session, IssuanceState::Completed).unwrap();

        // Already terminal
        assert!(transition(&mut session, IssuanceState::Failed).is_err());
    }

    #[test]
    fn test_pre_auth_flow_transitions() {
        let mut session = mock_session(FlowType::PreAuthorizedCode);
        assert_eq!(session.state, IssuanceState::AwaitingConsent);

        // Valid transition to TxCode
        let mut s1 = session.clone();
        transition(&mut s1, IssuanceState::AwaitingTxCode).unwrap();
        transition(&mut s1, IssuanceState::Processing).unwrap();

        // Valid transition directly to Processing
        let mut s2 = session.clone();
        transition(&mut s2, IssuanceState::Processing).unwrap();

        // Invalid transition for this flow
        assert!(transition(&mut session, IssuanceState::AwaitingAuthorization).is_err());
    }

    #[test]
    fn test_failed_transitions() {
        // Any non-terminal can fail
        let mut session = mock_session(FlowType::AuthorizationCode);
        transition(&mut session, IssuanceState::Failed).unwrap();

        let mut session = mock_session(FlowType::AuthorizationCode);
        transition(&mut session, IssuanceState::AwaitingAuthorization).unwrap();
        transition(&mut session, IssuanceState::Failed).unwrap();

        let mut session = mock_session(FlowType::PreAuthorizedCode);
        transition(&mut session, IssuanceState::AwaitingTxCode).unwrap();
        transition(&mut session, IssuanceState::Failed).unwrap();

        let mut session = mock_session(FlowType::PreAuthorizedCode);
        transition(&mut session, IssuanceState::Processing).unwrap();
        transition(&mut session, IssuanceState::Failed).unwrap();
    }

    #[test]
    fn test_invalid_flow_transitions() {
        // AwaitingAuthorization -> Processing is NOT allowed in PreAuthorizedCode flow
        let mut session = mock_session(FlowType::PreAuthorizedCode);
        session.state = IssuanceState::AwaitingAuthorization;
        assert!(transition(&mut session, IssuanceState::Processing).is_err());

        // AwaitingTxCode -> Processing is NOT allowed in AuthorizationCode flow
        let mut session = mock_session(FlowType::AuthorizationCode);
        session.state = IssuanceState::AwaitingTxCode;
        assert!(transition(&mut session, IssuanceState::Processing).is_err());
    }

    fn mock_presentation_context(
        response_mode: ResponseMode,
    ) -> cloud_wallet_openid4vc::oid4vp::client::PresentationContext {
        use cloud_wallet_openid4vc::oauth::authorization::OAuthAuthorizationRequest;
        use cloud_wallet_openid4vc::oid4vp::client::PresentationContext;
        use cloud_wallet_openid4vc::oid4vp::dcql::{
            CredentialFormat, CredentialMeta, CredentialQuery, DcqlQuery,
        };

        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_string(),
                format: CredentialFormat::DcSdJwt,
                multiple: None,
                meta: CredentialMeta::SdJwt {
                    vct_values: vec!["https://example.com/vct".to_string()],
                },
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
            }],
            credential_sets: None,
        };

        let client_id = cloud_wallet_openid4vc::oid4vp::client_id::ParsedClientId::parse(
            "redirect_uri:https://verifier.example.com",
        )
        .unwrap();

        PresentationContext {
            request: AuthorizationRequest {
                response_type: cloud_wallet_openid4vc::oid4vp::authorization::ResponseType::VpToken,
                nonce: "test-nonce".to_string(),
                response_mode: response_mode.clone(),
                oauth: OAuthAuthorizationRequest {
                    client_id: client_id.value().to_string(),
                    redirect_uri: None,
                    scope: None,
                    state: None,
                    nonce: None,
                    code_challenge: None,
                    code_challenge_method: None,
                },
                response_uri: Some(
                    url::Url::parse("https://verifier.example.com/response").unwrap(),
                ),
                request_uri: None,
                request_uri_method: None,
                dcql_query: Some(dcql_query.clone()),
                client_metadata: None,
                client_metadata_uri: None,
                request: None,
                transaction_data: None,
                verifier_info: None,
                expected_origins: None,
            },
            verifier_metadata: None,
            client_id,
            nonce: "test-nonce".to_string(),
            state: None,
            response_uri: Some(url::Url::parse("https://verifier.example.com/response").unwrap()),
            response_mode,
            dcql_query,
            transaction_data: vec![],
        }
    }

    fn mock_selection_result() -> SelectionResult {
        SelectionResult {
            candidates: std::collections::HashMap::new(),
            unsatisfied_queries: vec![],
            satisfies_query: true,
            selected_credential_query_ids: vec![],
            multiple_allowed_by_query_id: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_presentation_session_new_and_flow() {
        let ctx = mock_presentation_context(ResponseMode::DirectPost);
        let session = PresentationSession::new(Uuid::new_v4(), ctx, mock_selection_result());
        assert!(session.id.starts_with("prs_"));
        assert_eq!(session.state, PresentationState::AwaitingConsent);
        assert_eq!(session.flow, PresentationFlow::CrossDevice);

        assert_eq!(
            PresentationSession::new(
                Uuid::new_v4(),
                mock_presentation_context(ResponseMode::DcApi),
                mock_selection_result()
            )
            .flow,
            PresentationFlow::SameDevice
        );
        assert_eq!(
            PresentationSession::new(
                Uuid::new_v4(),
                mock_presentation_context(ResponseMode::DirectPostJwt),
                mock_selection_result()
            )
            .flow,
            PresentationFlow::CrossDevice
        );
        assert_eq!(
            PresentationSession::new(
                Uuid::new_v4(),
                mock_presentation_context(ResponseMode::DcApiJwt),
                mock_selection_result()
            )
            .flow,
            PresentationFlow::SameDevice
        );
    }

    #[test]
    fn test_transition_valid_terminal_states() {
        let ctx = mock_presentation_context(ResponseMode::DirectPost);
        let mut session =
            PresentationSession::new(Uuid::new_v4(), ctx.clone(), mock_selection_result());

        transition_presentation_session(&mut session, PresentationState::Completed).unwrap();
        assert_eq!(session.state, PresentationState::Completed);

        let mut session = PresentationSession::new(Uuid::new_v4(), ctx, mock_selection_result());
        transition_presentation_session(&mut session, PresentationState::Failed).unwrap();
        assert_eq!(session.state, PresentationState::Failed);
    }

    #[test]
    fn test_transition_rejected_when_not_awaiting_consent() {
        let ctx = mock_presentation_context(ResponseMode::DirectPost);

        // From Completed
        let mut s1 = PresentationSession::new(Uuid::new_v4(), ctx.clone(), mock_selection_result());
        transition_presentation_session(&mut s1, PresentationState::Completed).unwrap();
        assert!(transition_presentation_session(&mut s1, PresentationState::Failed).is_err());
        assert_eq!(s1.state, PresentationState::Completed);

        // From Failed
        let mut s2 = PresentationSession::new(Uuid::new_v4(), ctx.clone(), mock_selection_result());
        transition_presentation_session(&mut s2, PresentationState::Failed).unwrap();
        assert!(transition_presentation_session(&mut s2, PresentationState::Completed).is_err());
        assert_eq!(s2.state, PresentationState::Failed);

        // To AwaitingConsent (non-terminal target)
        let mut s3 = PresentationSession::new(Uuid::new_v4(), ctx, mock_selection_result());
        assert!(
            transition_presentation_session(&mut s3, PresentationState::AwaitingConsent).is_err()
        );
        assert_eq!(s3.state, PresentationState::AwaitingConsent);
    }

    #[test]
    fn test_presentation_session_serde_roundtrip() {
        let ctx = mock_presentation_context(ResponseMode::DirectPost);
        let original = PresentationSession::new(Uuid::new_v4(), ctx, mock_selection_result());

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: PresentationSession = serde_json::from_str(&serialized).unwrap();

        assert_eq!(original.id, deserialized.id);
        assert_eq!(original.tenant_id, deserialized.tenant_id);
        assert_eq!(original.state, deserialized.state);
        assert_eq!(original.flow, deserialized.flow);
    }
}
