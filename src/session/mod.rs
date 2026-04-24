use cloud_wallet_openid4vc::issuance::authz_server_metadata::AuthorizationServerMetadata;
use cloud_wallet_openid4vc::issuance::credential_offer::CredentialOffer;
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceState,
    pub offer: ParsedOffer,
    pub flow: FlowType,
    pub code_verifier: Option<String>,
    pub issuer_state: Option<String>,
    pub authz_server_metadata: AuthorizationServerMetadata,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    AuthorizationCode,
    PreAuthorizedCode,
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

pub type ParsedOffer = CredentialOffer;

impl IssuanceSession {
    pub fn new(
        tenant_id: Uuid,
        offer: ParsedOffer,
        flow: FlowType,
        authz_server_metadata: AuthorizationServerMetadata,
    ) -> Result<Self> {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::minutes(15);

        // Extract issuer_state from authorization_code grant if present
        let issuer_state = offer
            .grants
            .as_ref()
            .and_then(|g| g.authorization_code.as_ref())
            .and_then(|ac| ac.issuer_state.clone());

        Ok(Self {
            id: utils::generate_session_id(),
            tenant_id,
            state: IssuanceState::AwaitingConsent,
            offer,
            flow,
            code_verifier: None,
            issuer_state,
            authz_server_metadata,
            created_at: now,
            expires_at,
        })
    }

    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() >= self.expires_at
    }
}

pub fn transition(session: &mut IssuanceSession, new_state: IssuanceState) -> Result<()> {
    let allowed = is_transition_allowed(session.state, new_state, session.flow);
    if !allowed {
        color_eyre::eyre::bail!(
            "Invalid session state transition from {:?} to {:?}",
            session.state,
            new_state
        );
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
        // awaiting_consent -> failed (Consent rejected or any error)
        (AwaitingConsent, Failed) => true,
        // awaiting_authorization -> processing (Authorization callback received with valid code)
        (AwaitingAuthorization, Processing) if flow == AuthorizationCode => true,
        // awaiting_authorization -> failed (AS returns error or session expires)
        (AwaitingAuthorization, Failed) => true,
        // awaiting_tx_code -> processing (tx_code submitted)
        (AwaitingTxCode, Processing) if flow == PreAuthorizedCode => true,
        // awaiting_tx_code -> failed (Any error)
        (AwaitingTxCode, Failed) => true,
        // processing -> completed (Credential stored successfully)
        (Processing, Completed) => true,
        // processing -> failed (Token, credential, or deferred error)
        (Processing, Failed) => true,
        // Any non-terminal -> failed (POST /cancel or session expiry)
        (from, Failed) if !from.is_terminal() => true,

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_session(flow: FlowType) -> IssuanceSession {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_id"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "test_state"
                }
            }
        }))
        .unwrap();

        let authz_server_metadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as.example.com",
            "authorization_endpoint": "https://as.example.com/authorize",
            "token_endpoint": "https://as.example.com/token"
        }))
        .unwrap();

        IssuanceSession::new(Uuid::new_v4(), offer, flow, authz_server_metadata).unwrap()
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
}
