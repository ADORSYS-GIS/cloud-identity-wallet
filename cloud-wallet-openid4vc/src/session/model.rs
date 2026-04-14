//! Issuance session model.
//!
//! Captures every cryptographic and transactional artifact required across the
//! full OID4VCI lifecycle: PKCE state, c_nonce management, deferred issuance
//! transaction IDs, and SSE stream state.

use serde::{Deserialize, Serialize};
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

use crate::issuance::credential_offer::TxCode;

/// Serialize/deserialize [`time::UtcDateTime`] as a Unix timestamp (seconds).
mod utc_timestamp {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::UtcDateTime;

    pub fn serialize<S: Serializer>(dt: &UtcDateTime, s: S) -> Result<S::Ok, S::Error> {
        dt.unix_timestamp().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<UtcDateTime, D::Error> {
        let ts = i64::deserialize(d)?;
        UtcDateTime::from_unix_timestamp(ts).map_err(serde::de::Error::custom)
    }
}

/// `Option<UtcDateTime>` variant.
mod utc_timestamp_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::UtcDateTime;

    pub fn serialize<S: Serializer>(dt: &Option<UtcDateTime>, s: S) -> Result<S::Ok, S::Error> {
        dt.map(|d| d.unix_timestamp()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<UtcDateTime>, D::Error> {
        let opt = Option::<i64>::deserialize(d)?;
        opt.map(|ts| UtcDateTime::from_unix_timestamp(ts).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Default session TTL in seconds (15 minutes per the OID4VCI epic spec).
pub const DEFAULT_SESSION_TTL_SECS: i64 = 15 * 60;

/// Phase at which an issuance session failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStep {
    OfferResolution,
    Metadata,
    Authorization,
    Token,
    CredentialRequest,
    DeferredCredential,
    Internal,
}

/// Processing step for in-progress sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingStep {
    ExchangingToken,
    RequestingCredential,
    AwaitingDeferredCredential,
}

/// Lifecycle state of an issuance session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IssuanceSessionState {
    AwaitingConsent,
    AwaitingTxCode,
    Processing {
        step: ProcessingStep,
    },
    /// Credentials issued and stored (terminal).
    Completed,
    /// Unrecoverable error (terminal).
    Failed {
        error: String,
        error_description: Option<String>,
        step: FailureStep,
    },
}

impl IssuanceSessionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed { .. })
    }
}

/// Tracks OID4VCI flow state.
///
/// # Security
/// - `code_verifier`, `pre_authorized_code`, and `access_token` are secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceSession {
    pub session_id: String,
    pub tenant_id: Uuid,
    pub state: IssuanceSessionState,

    // Offer context
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub selected_configuration_ids: Vec<String>,

    // Auth-code flow
    pub code_verifier: Option<String>,
    pub oauth_state: Option<String>,
    pub issuer_state: Option<String>,

    // Pre-authorized code flow
    pub pre_authorized_code: Option<String>,
    pub tx_code_spec: Option<TxCode>,

    // Token exchange
    pub access_token: Option<String>,
    pub c_nonce: Option<String>,
    #[serde(with = "utc_timestamp_option")]
    pub c_nonce_expires_at: Option<UtcDateTime>,

    // Deferred issuance
    pub transaction_id: Option<String>,
    pub deferred_credential_endpoint: Option<Url>,

    // Timing
    #[serde(with = "utc_timestamp")]
    pub created_at: UtcDateTime,
    #[serde(with = "utc_timestamp")]
    pub expires_at: UtcDateTime,
}

impl IssuanceSession {
    pub fn new(
        tenant_id: Uuid,
        credential_issuer: String,
        credential_configuration_ids: Vec<String>,
        ttl_secs: i64,
    ) -> Self {
        let now = UtcDateTime::now();
        let expires_at = now + time::Duration::seconds(ttl_secs);

        Self {
            session_id: Uuid::new_v4().to_string(),
            tenant_id,
            state: IssuanceSessionState::AwaitingConsent,
            credential_issuer,
            credential_configuration_ids,
            selected_configuration_ids: Vec::new(),
            code_verifier: None,
            oauth_state: None,
            issuer_state: None,
            pre_authorized_code: None,
            tx_code_spec: None,
            access_token: None,
            c_nonce: None,
            c_nonce_expires_at: None,
            transaction_id: None,
            deferred_credential_endpoint: None,
            created_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        UtcDateTime::now() >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_defaults() {
        let tenant_id = Uuid::new_v4();
        let session = IssuanceSession::new(
            tenant_id,
            "https://issuer.example".to_string(),
            vec!["eu.europa.ec.eudi.pid.1".to_string()],
            DEFAULT_SESSION_TTL_SECS,
        );

        assert!(!session.session_id.is_empty());
        assert_eq!(session.tenant_id, tenant_id);
        assert_eq!(session.state, IssuanceSessionState::AwaitingConsent);
        assert!(!session.is_expired());
        assert!(session.expires_at > session.created_at);
    }

    #[test]
    fn expired_session_detected() {
        let session = IssuanceSession::new(
            Uuid::new_v4(),
            "https://issuer.example".to_string(),
            vec!["credential-type".to_string()],
            -1, // already expired
        );
        assert!(session.is_expired());
    }

    #[test]
    fn terminal_states() {
        assert!(IssuanceSessionState::Completed.is_terminal());
        assert!(
            IssuanceSessionState::Failed {
                error: "access_denied".to_string(),
                error_description: None,
                step: FailureStep::Authorization,
            }
            .is_terminal()
        );
        assert!(!IssuanceSessionState::AwaitingConsent.is_terminal());
        assert!(!IssuanceSessionState::AwaitingTxCode.is_terminal());
    }

    #[test]
    fn session_id_is_unique() {
        let a = IssuanceSession::new(
            Uuid::new_v4(),
            "https://issuer.example".to_string(),
            vec![],
            900,
        );
        let b = IssuanceSession::new(
            Uuid::new_v4(),
            "https://issuer.example".to_string(),
            vec![],
            900,
        );
        assert_ne!(a.session_id, b.session_id);
    }
}
