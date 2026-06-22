use crate::errors;
use crate::oid4vp::{
    RequestObjectError, RequestUriError, client_id::ClientIdParseError,
    presentation::PresentationBuilderError, response_mode::DirectPostError,
};

/// Errors from the OID4VP client orchestrator.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Raw request parsing failed.
    #[error("invalid authorization request: {0}")]
    InvalidRequest(String),

    /// Request URI resolution failed (transport, content-type, HTTP error).
    #[error(transparent)]
    RequestUriFailed(#[from] RequestUriError),

    /// Request Object JWT validation failed (signature, claims, expiry).
    #[error(transparent)]
    InvalidRequestObject(#[from] RequestObjectError),

    /// Client ID parsing failed.
    #[error(transparent)]
    InvalidClientId(#[from] ClientIdParseError),

    /// No DCQL query present in the request (scope-based not supported).
    #[error("no DCQL query in authorization request")]
    NoDcqlQuery,

    /// Transaction data decoding failed.
    #[error("invalid transaction data: {0}")]
    InvalidTransactionData(#[source] errors::Error),

    /// Authorization request validation failed.
    #[error("authorization request validation failed: {0}")]
    ValidationFailed(#[source] errors::Error),

    /// Verifier metadata or trust resolution failed.
    #[error("verifier resolution failed: {0}")]
    VerifierResolutionFailed(String),

    /// VP token construction failed.
    #[error(transparent)]
    PresentationBuildFailed(#[from] PresentationBuilderError),

    /// Response delivery to verifier failed.
    #[error(transparent)]
    ResponseDeliveryFailed(#[from] DirectPostError),

    /// No `response_uri` available for `direct_post` delivery.
    #[error("no response_uri available for direct_post response delivery")]
    NoResponseUri,

    /// Response mode is recognized but requires a handler not supplied here.
    #[error("unsupported response mode: {0}")]
    UnsupportedResponseMode(&'static str),
}
