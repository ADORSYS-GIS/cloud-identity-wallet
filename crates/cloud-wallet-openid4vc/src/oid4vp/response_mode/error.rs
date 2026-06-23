use thiserror::Error;

/// Errors that can occur when building or encrypting a `direct_post.jwt` response.
///
/// Covers the build/encrypt layer only. HTTP transport errors use [`DirectPostError`].
///
/// `PartialEq`/`Eq` compare string payloads verbatim. That's safe for variants whose
/// string content this crate controls (e.g. [`Self::UnsupportedAlgorithm`]'s message),
/// but [`Self::EncryptionFailed`] and [`Self::KeyConstruction`] may wrap text from an
/// external crypto primitive's `Display` impl. Don't assert equality against those two
/// variants with a hardcoded message — match on the variant instead.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JarmEncryptError {
    /// The selected JWK has no `alg` parameter. OID4VP §8.3 requires `alg` in the JWK.
    #[error("selected JWK has no 'alg' parameter; OID4VP §8.3 requires it")]
    MissingKeyAlgorithm,

    /// The JWK `alg` value is not a supported JWE key-management algorithm.
    #[error("JWK 'alg' value '{0}' is not supported for JWE encryption")]
    UnsupportedAlgorithm(String),

    /// Key material in the JWK is invalid or cannot be loaded.
    #[error("failed to construct encryption key from JWK: {0}")]
    KeyConstruction(String),

    /// Serializing the Authorization Response to JSON failed.
    #[error("failed to serialize authorization response: {0}")]
    SerializationError(String),

    /// JWE encryption failed.
    #[error("JWE encryption failed: {0}")]
    EncryptionFailed(String),
}

/// Errors that can occur when sending a `direct_post` Authorization Response.
///
/// `PartialEq`/`Eq` compare string payloads verbatim. [`Self::HttpRequestFailed`] and
/// [`Self::ResponseParseError`] wrap `reqwest`/`serde_json` error text, which is not
/// guaranteed stable across dependency upgrades — don't assert equality against those
/// two variants with a hardcoded message in tests; match on the variant instead.
/// [`Self::VerifierError`]/[`Self::HttpServerError`] are safe to compare exactly when
/// the `body` comes from a controlled test fixture (e.g. a mock server response).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectPostError {
    #[error("response_uri must use HTTPS")]
    HttpsRequired,

    #[error("response_uri does not match the expected URI from the authorization request")]
    UriMismatch,

    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(String),

    #[error("verifier returned client error {status}: {body}")]
    VerifierError { status: u16, body: String },

    #[error("HTTP server error {status}: {body}")]
    HttpServerError { status: u16, body: String },

    #[error("redirects are disabled for security, received status {status}")]
    RedirectNotFollowed { status: u16 },

    #[error("failed to parse verifier response: {0}")]
    ResponseParseError(String),

    /// Authorization Response encryption failed before any HTTP request was made.
    ///
    /// Preserves the structured [`JarmEncryptError`] so callers can distinguish a
    /// verifier misconfiguration (e.g. [`JarmEncryptError::MissingKeyAlgorithm`])
    /// from an internal crypto failure (e.g. [`JarmEncryptError::EncryptionFailed`]).
    #[error("failed to encrypt authorization response: {0}")]
    EncryptionFailed(#[from] JarmEncryptError),
}
