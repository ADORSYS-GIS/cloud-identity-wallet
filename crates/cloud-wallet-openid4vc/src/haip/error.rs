use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid HAIP URIscheme: expected 'haip-vci://' or 'haip-vp://', got '{0}'")]
    InvalidScheme(String),

    #[error("Missing required parameter '{0}' in HAIP URI")]
    MissingParameter(&'static str),

    #[error("Both '{0}' and '{1}' parameters are present; they are mutually exclusive")]
    MutuallyExclusive(&'static str, &'static str),

    #[error("Malformed HAIP URI: {0}")]
    MalformedUri(String),

    #[error("Duplicate parameter '{0}' in HAIP URI")]
    DuplicateParameter(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
