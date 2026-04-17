use cloud_wallet_openid4vc::issuance::credential_offer::CredentialOffer;
use color_eyre::eyre::Result;
pub use error::SessionError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod error;
pub mod memory;
pub mod util;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceState,
    pub offer: ParsedOffer,
    pub flow: FlowType,
    pub code_verifier: Option<String>,
    pub issuer_state: Option<String>,
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
    pub fn new(tenant_id: Uuid, offer: ParsedOffer, flow: FlowType) -> Result<Self> {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::minutes(15);
        Ok(Self {
            id: util::generate_session_id()?,
            tenant_id,
            state: IssuanceState::AwaitingConsent,
            offer,
            flow,
            code_verifier: None,
            issuer_state: None,
            created_at: now,
            expires_at,
        })
    }

    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() >= self.expires_at
    }
}

pub fn transition(
    session: &mut IssuanceSession,
    new_state: IssuanceState,
) -> std::result::Result<(), SessionError> {
    let allowed = is_transition_allowed(session.state, new_state, session.flow);
    if !allowed {
        return Err(SessionError::InvalidTransition {
            from: session.state,
            to: new_state,
        });
    }
    session.state = new_state;
    Ok(())
}

fn is_transition_allowed(from: IssuanceState, to: IssuanceState, flow: FlowType) -> bool {
    use FlowType::*;
    use IssuanceState::*;
    match (from, to) {
        (from, Failed) if !from.is_terminal() => true,
        (AwaitingConsent, AwaitingAuthorization) if flow == AuthorizationCode => true,
        (AwaitingConsent, AwaitingTxCode) if flow == PreAuthorizedCode => true,
        (AwaitingConsent, Processing) if flow == PreAuthorizedCode => true,
        (AwaitingAuthorization, Processing) => true,
        (AwaitingTxCode, Processing) => true,
        (Processing, Completed) => true,

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

        IssuanceSession::new(Uuid::new_v4(), offer, flow).unwrap()
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
        let session = mock_session(FlowType::AuthorizationCode);

        // Any non-terminal can fail
        let s1 = session.clone();
        assert!(is_transition_allowed(
            s1.state,
            IssuanceState::Failed,
            s1.flow
        ));

        let mut s2 = session.clone();
        transition(&mut s2, IssuanceState::AwaitingAuthorization).unwrap();
        transition(&mut s2, IssuanceState::Failed).unwrap();
    }
}
