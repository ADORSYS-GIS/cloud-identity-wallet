mod cancel;
mod tx_code;

#[cfg(test)]
mod tests;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

pub use cancel::cancel_session;
pub use tx_code::submit_tx_code;

#[derive(Debug, thiserror::Error)]
pub enum IssuanceError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session has expired")]
    SessionExpired,
    #[error("Invalid transaction code: {0}")]
    InvalidTxCode(String),
    #[error("Invalid session state: {0}")]
    InvalidSessionState(String),
    #[error("Session already in terminal state")]
    TerminalState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

impl From<&IssuanceError> for ErrorResponse {
    fn from(err: &IssuanceError) -> Self {
        match err {
            IssuanceError::SessionNotFound => Self {
                error: "session_not_found".to_string(),
                error_description: "No active session found for the given session_id.".to_string(),
            },
            IssuanceError::SessionExpired => Self {
                error: "session_expired".to_string(),
                error_description: "The session has expired.".to_string(),
            },
            IssuanceError::InvalidTxCode(desc) => Self {
                error: "invalid_tx_code".to_string(),
                error_description: desc.clone(),
            },
            IssuanceError::InvalidSessionState(desc) => Self {
                error: "invalid_session_state".to_string(),
                error_description: desc.clone(),
            },
            IssuanceError::TerminalState => Self {
                error: "invalid_session_state".to_string(),
                error_description:
                    "Session is already in a terminal state and cannot be cancelled.".to_string(),
            },
        }
    }
}

impl From<IssuanceError> for (StatusCode, axum::Json<ErrorResponse>) {
    fn from(err: IssuanceError) -> Self {
        let response = ErrorResponse::from(&err);
        let status = match &err {
            IssuanceError::SessionNotFound => StatusCode::NOT_FOUND,
            IssuanceError::SessionExpired => StatusCode::NOT_FOUND,
            IssuanceError::InvalidTxCode(_) => StatusCode::BAD_REQUEST,
            IssuanceError::InvalidSessionState(_) => StatusCode::CONFLICT,
            IssuanceError::TerminalState => StatusCode::CONFLICT,
        };
        (status, axum::Json(response))
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct TxCodeRequest {
    pub tx_code: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TxCodeResponse {
    pub session_id: String,
}
