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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
            grants: offer
                .grants
                .map(SessionGrantsData::from)
                .unwrap_or_default(),
        }
    }
}

impl From<Grants> for SessionGrantsData {
    fn from(grants: Grants) -> Self {
        Self {
            authorization_code: grants
                .authorization_code
                .map(SessionAuthorizationCodeGrant::from),
            pre_authorized_code: grants
                .pre_authorized_code
                .map(SessionPreAuthorizedCodeGrant::from),
        }
    }
}

impl From<cloud_wallet_openid4vc::issuance::credential_offer::AuthorizationCodeGrant>
    for SessionAuthorizationCodeGrant
{
    fn from(
        grant: cloud_wallet_openid4vc::issuance::credential_offer::AuthorizationCodeGrant,
    ) -> Self {
        Self {
            issuer_state: grant.issuer_state,
            authorization_server: grant.authorization_server,
        }
    }
}

impl From<cloud_wallet_openid4vc::issuance::credential_offer::PreAuthorizedCodeGrant>
    for SessionPreAuthorizedCodeGrant
{
    fn from(
        grant: cloud_wallet_openid4vc::issuance::credential_offer::PreAuthorizedCodeGrant,
    ) -> Self {
        // NOTE: pre_authorized_code (the sensitive single-use token) is intentionally
        // NOT stored in the session to prevent token replay if the session store is compromised.
        Self {
            tx_code: grant.tx_code,
            authorization_server: grant.authorization_server,
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
        let expires_at =
            OffsetDateTime::now_utc() + time::Duration::seconds(DEFAULT_SESSION_TTL_SECS);
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

    #[test]
    fn test_issuance_session_new_initializes_correctly() {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_cred"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "state123"
                }
            }
        }))
        .unwrap();

        let tenant_id = Uuid::new_v4();
        let session = IssuanceSession::new(tenant_id, offer, FlowType::AuthorizationCode);

        assert!(session.id.starts_with("ses_"));
        assert_eq!(session.tenant_id, tenant_id);
        assert_eq!(session.state, IssuanceState::AwaitingConsent);
        assert_eq!(session.flow, FlowType::AuthorizationCode);
        assert!(session.code_verifier.is_none());
        assert!(session.issuer_state.is_none());
        assert!(session.expires_at > OffsetDateTime::now_utc());
    }

    #[test]
    fn test_issuance_session_new_pre_authorized_code() {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_cred"],
            "grants": {
                "pre_authorized_code": {
                    "tx_code": {
                        "input_mode": "numeric",
                        "length": 6
                    }
                }
            }
        }))
        .unwrap();

        let session = IssuanceSession::new(Uuid::new_v4(), offer, FlowType::PreAuthorizedCode);
        assert_eq!(session.flow, FlowType::PreAuthorizedCode);
        assert_eq!(session.state, IssuanceState::AwaitingConsent);
    }

    #[test]
    fn test_issuance_session_is_expired() {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test"],
            "grants": {}
        }))
        .unwrap();

        let mut session = IssuanceSession::new(Uuid::new_v4(), offer, FlowType::PreAuthorizedCode);
        assert!(!session.is_expired());

        // Manually set to past
        session.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert!(session.is_expired());
    }

    #[test]
    fn test_issuance_state_is_terminal() {
        assert!(IssuanceState::Completed.is_terminal());
        assert!(IssuanceState::Failed.is_terminal());
        assert!(!IssuanceState::AwaitingConsent.is_terminal());
        assert!(!IssuanceState::AwaitingAuthorization.is_terminal());
        assert!(!IssuanceState::AwaitingTxCode.is_terminal());
        assert!(!IssuanceState::Processing.is_terminal());
    }

    #[test]
    fn test_session_grants_data_default() {
        let grants = SessionGrantsData::default();
        assert!(grants.authorization_code.is_none());
        assert!(grants.pre_authorized_code.is_none());
    }

    #[test]
    fn test_flow_type_display() {
        assert_eq!(
            format!("{}", FlowType::AuthorizationCode),
            "authorization_code"
        );
        assert_eq!(
            format!("{}", FlowType::PreAuthorizedCode),
            "pre_authorized_code"
        );
    }

    #[test]
    fn test_session_offer_data_from_credential_offer_no_grants() {
        let offer: CredentialOffer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test"],
        }))
        .unwrap();

        let session_offer: SessionOfferData = offer.into();
        assert_eq!(session_offer.credential_configuration_ids, vec!["test"]);
        assert!(session_offer.grants.authorization_code.is_none());
        assert!(session_offer.grants.pre_authorized_code.is_none());
    }

    #[test]
    fn test_session_offer_data_from_credential_offer_with_pre_authorized_grant() {
        let offer: CredentialOffer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "test_code_abc"
                }
            }
        }))
        .unwrap();

        let session_offer: SessionOfferData = offer.into();
        assert!(session_offer.grants.authorization_code.is_none());
        assert!(session_offer.grants.pre_authorized_code.is_some());
    }

    #[test]
    fn test_expired_session_transition_fails() {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test"],
            "grants": {}
        }))
        .unwrap();

        let mut session = IssuanceSession::new(Uuid::new_v4(), offer, FlowType::PreAuthorizedCode);
        session.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);

        let result = transition(&mut session, IssuanceState::Processing);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::ExpiredSession => {}
            _ => panic!("Expected ExpiredSession error"),
        }
    }

    #[test]
    fn test_session_serialization_roundtrip() {
        let offer = serde_json::from_value(serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["test_id"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "state123"
                }
            }
        }))
        .unwrap();

        let session = IssuanceSession::new(Uuid::new_v4(), offer, FlowType::AuthorizationCode);
        let serialized = serde_json::to_string(&session).unwrap();
        let deserialized: IssuanceSession = serde_json::from_str(&serialized).unwrap();

        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.state, deserialized.state);
        assert_eq!(session.flow, deserialized.flow);
    }
}
