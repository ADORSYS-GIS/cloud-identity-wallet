use thiserror::Error;

use crate::oid4vp::authorization::VpTokenError;

#[derive(Debug, Error)]
pub enum PresentationBuilderError {
    #[error("No credentials selected for presentation")]
    NoCredentialsSelected,
    #[error("Credential query ID '{0}' not found in DCQL query")]
    QueryNotFound(String),
    #[error(transparent)]
    VpToken(#[from] VpTokenError),
    #[error(
        "VP token entry '{query_id}' contains multiple presentations but the credential query does not allow multiple"
    )]
    MultiplePresentationsNotAllowed { query_id: String },
}

/// Errors that can occur during holder binding proof creation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HolderBindingProofError {
    /// Proof signing failed (e.g., cryptographic signing error).
    #[error("holder binding proof signing failed: {0}")]
    SigningFailed(String),
    /// Invalid key material (e.g., malformed key, unsupported key type).
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
    /// Unsupported cryptographic algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Missing required field for proof creation.
    #[error("missing required field: {0}")]
    MissingRequiredField(String),
}
