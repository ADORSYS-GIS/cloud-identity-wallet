use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use cloud_wallet_openid4vc::issuance::credential_offer::{InputMode, TxCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    AwaitingConsent,
    AwaitingTxCode,
    Processing,
    Completed,
    Failed,
}

impl SessionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingStep {
    ExchangingToken,
    RequestingCredential,
    AwaitingDeferredCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCodeSpec {
    pub input_mode: InputMode,
    pub length: Option<u32>,
    pub description: Option<String>,
}

impl From<TxCode> for TxCodeSpec {
    fn from(tx_code: TxCode) -> Self {
        Self {
            input_mode: tx_code.input_mode.unwrap_or_default(),
            length: tx_code.length,
            description: tx_code.description,
        }
    }
}

impl TxCodeSpec {
    pub fn validate_tx_code(&self, code: &str) -> Result<(), TxCodeValidationError> {
        if let Some(length) = self.length
            && code.len() != length as usize
        {
            return Err(TxCodeValidationError::InvalidLength {
                expected: length,
                actual: code.len() as u32,
            });
        }

        match self.input_mode {
            InputMode::Numeric => {
                if !code.chars().all(|c| c.is_ascii_digit()) {
                    return Err(TxCodeValidationError::InvalidCharacters {
                        expected: "numeric".to_string(),
                    });
                }
            }
            InputMode::Text => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxCodeValidationError {
    InvalidLength { expected: u32, actual: u32 },
    InvalidCharacters { expected: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub tenant_id: Uuid,
    pub state: SessionState,
    pub tx_code_spec: Option<TxCodeSpec>,
    pub submitted_tx_code: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl Session {
    pub fn new(id: String, tenant_id: Uuid, tx_code_spec: Option<TxCodeSpec>) -> Self {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::minutes(10);

        Self {
            id,
            tenant_id,
            state: SessionState::AwaitingConsent,
            tx_code_spec,
            submitted_tx_code: None,
            created_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() > self.expires_at
    }
}
