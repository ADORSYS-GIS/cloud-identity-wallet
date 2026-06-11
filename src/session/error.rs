use std::borrow::Cow;

/// Session errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failure in storage backend: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Encoding or decoding error: {0}")]
    Encoding(#[from] serde_json::Error),

    #[error("Invalid state transition from {0} to {1}")]
    InvalidStateTransition(Cow<'static, str>, Cow<'static, str>),

    #[error("{0}")]
    Other(color_eyre::eyre::Report),
}

/// Presentation session store errors.
#[derive(thiserror::Error, Debug)]
pub enum PresentationSessionStoreError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Invalid session state")]
    InvalidSessionState,

    #[error("Store error: {0}")]
    Store(#[from] Error),
}
