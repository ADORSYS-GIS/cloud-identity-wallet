use std::borrow::Cow;

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
///
/// Used by all credential formats (SD-JWT VC, mdoc, etc.) that implement
/// the [`PresentationFactory`](super::PresentationFactory) trait.
#[derive(Debug, Error)]
pub enum ProofError {
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
    MissingRequiredField(Cow<'static, str>),
    /// Invalid proof input.
    #[error("invalid proof input: {0}")]
    InvalidInput(Cow<'static, str>),
    /// Format-specific processing error (e.g. SD-JWT, mdoc).
    #[error(transparent)]
    Format(Box<dyn std::error::Error + Send + Sync>),
}

impl From<crate::formats::sd_jwt::Error> for ProofError {
    fn from(value: crate::formats::sd_jwt::Error) -> Self {
        Self::Format(Box::new(value))
    }
}

impl From<serde_json::Error> for ProofError {
    fn from(value: serde_json::Error) -> Self {
        Self::Format(Box::new(value))
    }
}
