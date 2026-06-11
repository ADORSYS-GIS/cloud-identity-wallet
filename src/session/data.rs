use cloud_wallet_openid4vc::oid4vci::client::ResolvedOfferContext;
use cloud_wallet_openid4vc::oid4vp::authorization::{AuthorizationRequest, ResponseMode};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: PresentationState,
    pub resolved_request: AuthorizationRequest,
    pub dcql_result: SelectionResult,
    pub flow: PresentationFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationState {
    AwaitingConsent,
    Completed,
    Failed,
}

impl PresentationState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationFlow {
    CrossDevice,
    SameDevice,
}

impl PresentationSession {
    pub fn new(
        tenant_id: Uuid,
        resolved_request: AuthorizationRequest,
        dcql_result: SelectionResult,
    ) -> Self {
        let flow = match resolved_request.response_mode {
            ResponseMode::DcApi | ResponseMode::DcApiJwt => PresentationFlow::SameDevice,
            _ => PresentationFlow::CrossDevice,
        };
        Self {
            id: utils::generate_presentation_session_id(),
            tenant_id,
            state: PresentationState::AwaitingConsent,
            resolved_request,
            dcql_result,
            flow,
        }
    }
}

pub fn transition_presentation(
    session: &mut PresentationSession,
    new_state: PresentationState,
) -> Result<()> {
    if session.state != PresentationState::AwaitingConsent {
        return Err(SessionError::InvalidStateTransition(
            format!("{:?}", session.state).into(),
            format!("{:?}", new_state).into(),
        ));
    }
    if new_state == PresentationState::AwaitingConsent {
        return Err(SessionError::InvalidStateTransition(
            format!("{:?}", session.state).into(),
            format!("{:?}", new_state).into(),
        ));
    }
    session.state = new_state;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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

    fn mock_presentation_session(response_mode: ResponseMode) -> PresentationSession {
        use cloud_wallet_openid4vc::oid4vp::dcql::DcqlQuery;
        let request = AuthorizationRequest {
            response_type: cloud_wallet_openid4vc::oid4vp::authorization::ResponseType::VpToken,
            client_id: "client".to_string(),
            redirect_uri: None,
            scope: None,
            state: None,
            nonce: "nonce".to_string(),
            response_mode,
            response_uri: Some(url::Url::parse("https://example.com/response").unwrap()),
            request_uri: None,
            request_uri_method: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![],
                credential_sets: None,
            }),
            client_metadata: None,
            client_metadata_uri: None,
            request: None,
            transaction_data: None,
            verifier_info: None,
            expected_origins: None,
        };
        let dcql_result = SelectionResult {
            candidates: std::collections::HashMap::new(),
            unsatisfied_queries: vec![],
            satisfies_query: true,
            selected_credential_query_ids: vec![],
            multiple_allowed_by_query_id: std::collections::HashMap::new(),
        };
        PresentationSession::new(Uuid::new_v4(), request, dcql_result)
    }

    #[test]
    fn test_presentation_flow_from_response_mode() {
        let session = mock_presentation_session(ResponseMode::DirectPost);
        assert_eq!(session.flow, PresentationFlow::CrossDevice);

        let session = mock_presentation_session(ResponseMode::DirectPostJwt);
        assert_eq!(session.flow, PresentationFlow::CrossDevice);

        let session = mock_presentation_session(ResponseMode::DcApi);
        assert_eq!(session.flow, PresentationFlow::SameDevice);

        let session = mock_presentation_session(ResponseMode::DcApiJwt);
        assert_eq!(session.flow, PresentationFlow::SameDevice);
    }

    #[test]
    fn test_presentation_valid_transitions() {
        let mut session = mock_presentation_session(ResponseMode::DirectPost);
        assert_eq!(session.state, PresentationState::AwaitingConsent);

        transition_presentation(&mut session, PresentationState::Completed).unwrap();
        assert_eq!(session.state, PresentationState::Completed);

        let mut session = mock_presentation_session(ResponseMode::DirectPost);
        transition_presentation(&mut session, PresentationState::Failed).unwrap();
        assert_eq!(session.state, PresentationState::Failed);
    }

    #[test]
    fn test_presentation_invalid_transitions_from_terminal() {
        let mut session = mock_presentation_session(ResponseMode::DirectPost);
        transition_presentation(&mut session, PresentationState::Completed).unwrap();
        assert!(transition_presentation(&mut session, PresentationState::Failed).is_err());

        let mut session = mock_presentation_session(ResponseMode::DirectPost);
        transition_presentation(&mut session, PresentationState::Failed).unwrap();
        assert!(transition_presentation(&mut session, PresentationState::Completed).is_err());
    }

    #[test]
    fn test_presentation_invalid_transition_to_awaiting_consent() {
        let mut session = mock_presentation_session(ResponseMode::DirectPost);
        assert!(transition_presentation(&mut session, PresentationState::AwaitingConsent).is_err());
    }
}
