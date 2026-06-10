use thiserror::Error;

/// Errors that can occur when sending a `direct_post` Authorization Response.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectPostError {
    #[error("response_uri must use HTTPS")]
    HttpsRequired,

    #[error("response_uri does not match the expected URI from the authorization request")]
    UriMismatch,

    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(String),

    #[error("HTTP error {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("failed to parse verifier response: {0}")]
    ResponseParseError(String),
}
