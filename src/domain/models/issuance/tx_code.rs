use cloud_wallet_openid4vc::issuance::credential_offer::{InputMode, TxCode};
use serde::{Deserialize, Serialize};

use crate::session::{IssuanceState, SessionError};

/// Request body for submitting a transaction code.
#[derive(Debug, Clone, Deserialize)]
pub struct TxCodeRequest {
    pub tx_code: String,
}

impl TxCodeRequest {
    pub fn value(&self) -> Result<&str, TxCodeError> {
        if self.tx_code.is_empty() {
            return Err(TxCodeError::invalid_tx_code(
                "Transaction code is required.",
            ));
        }
        Ok(self.tx_code.as_str())
    }

    pub fn validate_against(&self, spec: &TxCode) -> Result<(), TxCodeError> {
        let tx_code = self.value()?;
        let numeric = spec.input_mode.unwrap_or_default() == InputMode::Numeric;
        let expected_len = spec.length.map(|length| length as usize);

        let has_invalid_chars = numeric && !tx_code.bytes().all(|byte| byte.is_ascii_digit());
        let has_invalid_len = expected_len.is_some_and(|length| tx_code.chars().count() != length);

        if has_invalid_chars || has_invalid_len {
            return Err(TxCodeError::invalid_tx_code(tx_code_error_description(
                numeric,
                expected_len,
            )));
        }
        Ok(())
    }
}

/// Response body returned when a transaction code is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TxCodeResponse {
    pub session_id: String,
}

/// Errors specific to transaction-code submission.
#[derive(Debug, thiserror::Error)]
pub enum TxCodeError {
    #[error("{0}")]
    InvalidTxCode(String),

    #[error("No active session found for session_id {0}.")]
    SessionNotFound(String),

    #[error("{0}")]
    InvalidSessionState(String),

    #[error("error storing session: {0}")]
    SessionStore(#[from] SessionError),
}

impl TxCodeError {
    pub fn invalid_tx_code(description: impl Into<String>) -> Self {
        Self::InvalidTxCode(description.into())
    }

    pub fn session_not_found(session_id: impl Into<String>) -> Self {
        Self::SessionNotFound(session_id.into())
    }

    pub fn invalid_session_state(description: impl Into<String>) -> Self {
        Self::InvalidSessionState(description.into())
    }

    pub fn not_awaiting_tx_code(state: IssuanceState) -> Self {
        Self::invalid_session_state(format!(
            "Session is not awaiting a transaction code (current state: {state:?}).",
        ))
    }

    pub fn tx_code_not_required() -> Self {
        Self::invalid_session_state("Session does not require a transaction code.")
    }

    pub fn not_pre_authorized_flow() -> Self {
        Self::invalid_session_state("Session is not a pre-authorized code flow.")
    }

    pub fn error_description(&self) -> String {
        match self {
            Self::InvalidTxCode(description) | Self::InvalidSessionState(description) => {
                description.clone()
            }
            Self::SessionNotFound(session_id) => {
                format!("No active session found for session_id {session_id}.")
            }
            Self::SessionStore(error) => format!("error storing session: {error}"),
        }
    }
}

fn tx_code_error_description(numeric: bool, expected_len: Option<usize>) -> String {
    match (numeric, expected_len) {
        (true, Some(length)) => {
            format!("Transaction code must be exactly {length} numeric digits.")
        }
        (true, None) => "Transaction code must contain only ASCII digits.".to_owned(),
        (false, Some(length)) => {
            format!("Transaction code must be exactly {length} characters.")
        }
        (false, None) => "Transaction code is invalid.".to_owned(),
    }
}
