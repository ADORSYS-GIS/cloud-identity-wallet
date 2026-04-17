use super::IssuanceState;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Invalid session state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: IssuanceState,
        to: IssuanceState,
    },
    #[error("Session not found")]
    NotFound,
    #[error("Session expired")]
    Expired,
    #[error("Other error: {0}")]
    Other(String),
}
