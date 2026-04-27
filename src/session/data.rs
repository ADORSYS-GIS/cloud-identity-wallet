use cloud_wallet_openid4vc::issuance::credential_offer::{CredentialOffer, Grants};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::session::Result;
use crate::session::SessionError;
use crate::session::utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceState,
    pub offer: SessionOfferData,
    pub flow: FlowType,
    pub code_verifier: Option<String>,
    pub issuer_state: Option<String>,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOfferData {
    pub credential_issuer: url::Url,
    pub credential_configuration_ids: Vec<String>,
    pub grants: SessionGrantsData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrantsData {
    pub authorization_code: Option<SessionAuthorizationCodeGrant>,
    pub pre_authorized_code: Option<SessionPreAuthorizedCodeGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<url::Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPreAuthorizedCodeGrant {
    pub tx_code: Option<cloud_wallet_openid4vc::issuance::credential_offer::TxCode>,
    pub authorization_server: Option<url::Url>,
}

impl From<CredentialOffer> for SessionOfferData {
    fn from(offer: CredentialOffer) -> Self {
        Self {
            credential_issuer: offer.credential_issuer,
            credential_configuration_ids: offer.credential_configuration_ids,
            grants: offer.grants.map(SessionGrantsData::from).unwrap_or_default(),
        }
    }
}

impl From<Grants> for SessionGrantsData {
    fn from(grants: Grants) -> Self {
        Self {
            authorization_code: grants.authorization_code.map(SessionAuthorizationCodeGrant::from),
            pre_authorized_code: grants
                .pre_authorized_code
                .map(SessionPreAuthorizedCodeGrant::from),
        }
    }
}

impl From<cloud_wallet_openid4vc::issuance::credential_offer::AuthorizationCodeGrant>
    for SessionAuthorizationCodeGrant
{
    fn from(grant: cloud_wallet_openid4vc::issuance::credential_offer::AuthorizationCodeGrant) -> Self {
        Self {
            issuer_state: grant.issuer_state,
            authorization_server: grant.authorization_server,
        }
    }
}

impl From<cloud_wallet_openid4vc::issuance::credential_offer::PreAuthorizedCodeGrant>
    for SessionPreAuthorizedCodeGrant
{
    fn from(grant: cloud_wallet_openid4vc::issuance::credential_offer::PreAuthorizedCodeGrant) -> Self {
        // NOTE: pre_authorized_code (the sensitive single-use token) is intentionally
        // NOT stored in the session to prevent token replay if the session store is compromised.
        Self {
            tx_code: grant.tx_code,
            authorization_server: grant.authorization_server,
        }
    }
}

impl Default for SessionGrantsData {
    fn default() -> Self {
        Self {
            authorization_code: None,
            pre_authorized_code: None,
        }
    }
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

const DEFAULT_SESSION_TTL_SECS: i64 = 3600;

impl IssuanceSession {
    pub fn new(tenant_id: Uuid, offer: ParsedOffer, flow: FlowType) -> Self {
        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(DEFAULT_SESSION_TTL_SECS);
        Self {
            id: utils::generate_session_id(),
            tenant_id,
            state: IssuanceState::AwaitingConsent,
            offer: offer.into(),
            flow,
            code_verifier: None,
            issuer_state: None,
            expires_at,
        }
    }

    /// Returns true if this session has expired.
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() >= self.expires_at
    }
}

pub fn transition(session: &mut IssuanceSession, new_state: IssuanceState) -> Result<()> {
    if session.is_expired() {
        return Err(SessionError::ExpiredSession);
    }
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

        IssuanceSession::new(Uuid::new_v4(), offer, flow)
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
