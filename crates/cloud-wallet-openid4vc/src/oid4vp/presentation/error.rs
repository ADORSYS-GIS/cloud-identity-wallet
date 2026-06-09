use thiserror::Error;

#[derive(Debug, Error)]
pub enum PresentationBuilderError {
    #[error("No credentials selected for presentation")]
    NoCredentialsSelected,
    #[error("Credential query ID '{0}' not found in DCQL query")]
    QueryNotFound(String),
    #[error(transparent)]
    VpToken(#[from] VpTokenError),
}

#[derive(Debug, Error)]
pub enum VpTokenError {
    #[error("VP token must contain at least one credential query entry")]
    Empty,
    #[error("VP token entry '{query_id}' is not a valid DCQL credential query id")]
    InvalidQueryId { query_id: String },
    #[error("VP token entry '{query_id}' must contain at least one presentation")]
    EmptyPresentationList { query_id: String },
    #[error(
        "VP token entry '{query_id}' contains multiple presentations but the credential query does not allow multiple"
    )]
    MultiplePresentationsNotAllowed { query_id: String },
}
