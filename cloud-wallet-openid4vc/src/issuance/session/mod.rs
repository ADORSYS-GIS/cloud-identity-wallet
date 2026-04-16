use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use uuid::Uuid;

use crate::errors::{Error, ErrorKind, Result};
use crate::issuance::credential_offer::CredentialOffer;

pub mod store;

#[cfg(feature = "memory-session")]
pub mod memory;

#[cfg(feature = "redis-session")]
pub mod redis;

pub fn generate_session_id() -> Result<String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use cloud_wallet_crypto::rand;

    let mut bytes = [0u8; 16];
    rand::fill_bytes(&mut bytes).map_err(|e| Error::new(ErrorKind::Other, e))?;
    Ok(format!("ses_{}", URL_SAFE_NO_PAD.encode(bytes)))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceState,
    pub offer: ParsedOffer,
    pub flow: FlowType,
    pub code_verifier: Option<String>,
    pub issuer_state: Option<String>,
    pub created_at: UtcDateTime,
    pub expires_at: UtcDateTime,
}

impl IssuanceSession {
    pub fn new(tenant_id: Uuid, offer: ParsedOffer, flow: FlowType) -> Result<Self> {
        let now = UtcDateTime::now();
        let expires_at = now + time::Duration::minutes(15);
        Ok(Self {
            id: generate_session_id()?,
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
        UtcDateTime::now() >= self.expires_at
    }
}

pub fn transition(session: &mut IssuanceSession, new_state: IssuanceState) -> Result<()> {
    let allowed = is_transition_allowed(session.state, new_state);
    if !allowed {
        return Err(Error::message(
            ErrorKind::InvalidSessionState,
            format!(
                "transition from {:?} to {:?} is not allowed",
                session.state, new_state
            ),
        ));
    }
    session.state = new_state;
    Ok(())
}

fn is_transition_allowed(from: IssuanceState, to: IssuanceState) -> bool {
    use IssuanceState::*;
    match (from, to) {
        // Any non-terminal → Failed (POST /cancel or expiry)
        (from, Failed) if !from.is_terminal() => true,

        (AwaitingConsent, AwaitingAuthorization) => true,
        (AwaitingConsent, AwaitingTxCode) => true,
        (AwaitingConsent, Processing) => true,

        (AwaitingAuthorization, Processing) => true,

        (AwaitingTxCode, Processing) => true,

        (Processing, Completed) => true,

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_offer() -> ParsedOffer {
        use crate::issuance::credential_offer::CredentialOffer;
        CredentialOffer {
            credential_issuer: "https://issuer.example.com".into(),
            credential_configuration_ids: vec!["TestCredential".into()],
            grants: None,
        }
    }

    fn make_session() -> IssuanceSession {
        IssuanceSession::new(Uuid::new_v4(), make_offer(), FlowType::AuthorizationCode).unwrap()
    }

    #[test]
    fn session_id_has_ses_prefix() {
        let s = make_session();
        assert!(
            s.id.starts_with("ses_"),
            "id must start with ses_: {}",
            s.id
        );
    }

    #[test]
    fn session_id_has_128_bit_entropy() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let s = make_session();
        let b64 = s.id.strip_prefix("ses_").unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(b64).unwrap();
        assert_eq!(
            bytes.len(),
            16,
            "session id must encode 16 bytes (128 bits)"
        );
    }

    #[test]
    fn initial_state_is_awaiting_consent() {
        assert_eq!(make_session().state, IssuanceState::AwaitingConsent);
    }

    #[test]
    fn expires_at_is_15_minutes_after_creation() {
        let s = make_session();
        let diff = s.expires_at - s.created_at;
        assert_eq!(diff.whole_minutes(), 15);
    }

    // ── Valid transitions ────────────────────────────────────────────

    #[test]
    fn consent_to_awaiting_authorization() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingAuthorization).unwrap();
        assert_eq!(s.state, IssuanceState::AwaitingAuthorization);
    }

    #[test]
    fn consent_to_awaiting_tx_code() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingTxCode).unwrap();
        assert_eq!(s.state, IssuanceState::AwaitingTxCode);
    }

    #[test]
    fn consent_to_processing() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::Processing).unwrap();
        assert_eq!(s.state, IssuanceState::Processing);
    }

    #[test]
    fn consent_to_failed() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::Failed).unwrap();
        assert_eq!(s.state, IssuanceState::Failed);
    }

    #[test]
    fn awaiting_authorization_to_processing() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingAuthorization).unwrap();
        transition(&mut s, IssuanceState::Processing).unwrap();
        assert_eq!(s.state, IssuanceState::Processing);
    }

    #[test]
    fn awaiting_authorization_to_failed() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingAuthorization).unwrap();
        transition(&mut s, IssuanceState::Failed).unwrap();
        assert_eq!(s.state, IssuanceState::Failed);
    }

    #[test]
    fn awaiting_tx_code_to_processing() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingTxCode).unwrap();
        transition(&mut s, IssuanceState::Processing).unwrap();
        assert_eq!(s.state, IssuanceState::Processing);
    }

    #[test]
    fn awaiting_tx_code_to_failed() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingTxCode).unwrap();
        transition(&mut s, IssuanceState::Failed).unwrap();
        assert_eq!(s.state, IssuanceState::Failed);
    }

    #[test]
    fn processing_to_completed() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::Processing).unwrap();
        transition(&mut s, IssuanceState::Completed).unwrap();
        assert_eq!(s.state, IssuanceState::Completed);
    }

    #[test]
    fn processing_to_failed() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::Processing).unwrap();
        transition(&mut s, IssuanceState::Failed).unwrap();
        assert_eq!(s.state, IssuanceState::Failed);
    }

    // ── Invalid transitions ──────────────────────────────────────────

    #[test]
    fn terminal_to_any_is_invalid() {
        for terminal in [IssuanceState::Completed, IssuanceState::Failed] {
            for target in [
                IssuanceState::AwaitingConsent,
                IssuanceState::AwaitingAuthorization,
                IssuanceState::AwaitingTxCode,
                IssuanceState::Processing,
                IssuanceState::Completed,
                IssuanceState::Failed,
            ] {
                let mut s = make_session();
                s.state = terminal;
                let err = transition(&mut s, target).unwrap_err();
                assert_eq!(
                    err.kind(),
                    ErrorKind::InvalidSessionState,
                    "{terminal:?} → {target:?} must be invalid"
                );
            }
        }
    }

    #[test]
    fn awaiting_authorization_to_consent_is_invalid() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingAuthorization).unwrap();
        let err = transition(&mut s, IssuanceState::AwaitingConsent).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSessionState);
    }

    #[test]
    fn awaiting_tx_code_to_awaiting_authorization_is_invalid() {
        let mut s = make_session();
        transition(&mut s, IssuanceState::AwaitingTxCode).unwrap();
        let err = transition(&mut s, IssuanceState::AwaitingAuthorization).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSessionState);
    }

    #[test]
    fn consent_to_completed_is_invalid() {
        let mut s = make_session();
        let err = transition(&mut s, IssuanceState::Completed).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSessionState);
    }
}
