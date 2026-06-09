use thiserror::Error;

#[derive(Debug, Error)]
pub enum PresentationBuilderError {
    #[error("No credentials selected for presentation")]
    NoCredentialsSelected,
    #[error("Credential query ID '{0}' not found in DCQL query")]
    QueryNotFound(String),
    #[error("Failed to build VP token: {0}")]
    VpTokenBuild(String),
}
