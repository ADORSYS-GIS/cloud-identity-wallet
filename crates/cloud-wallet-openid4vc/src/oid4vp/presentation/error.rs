use thiserror::Error;

#[derive(Debug, Error)]
pub enum PresentationBuilderError {
    #[error("No credentials selected for presentation")]
    NoCredentialsSelected,
    #[error("Credential query ID '{0}' not found in DCQL query")]
    QueryNotFound(String),
    #[error(
        "Format mismatch: credential format '{credential_format}' does not match query format '{query_format}'"
    )]
    FormatMismatch {
        credential_format: String,
        query_format: String,
    },
    #[error("Invalid VP token: {0}")]
    InvalidVpToken(String),
}

#[derive(Debug, Error)]
pub enum VpTokenBuilderError {
    #[error("VP token must contain at least one credential query entry")]
    EmptyEntries,
    #[error("VP token entry '{query_id}' must contain at least one presentation")]
    EmptyPresentation { query_id: String },
    #[error("Invalid DCQL query identifier: {0}")]
    InvalidQueryId(String),
}
