use std::borrow::Cow;

/// Session errors.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failure in storage backend: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Encoding or decoding error: {0}")]
    Encoding(#[from] postcard::Error),

    #[error("Invalid state transition from {0} to {1}")]
    InvalidStateTransition(Cow<'static, str>, Cow<'static, str>),

    #[error("session has expired")]
    ExpiredSession,

    #[error("{0}")]
    Other(color_eyre::eyre::Report),
}
