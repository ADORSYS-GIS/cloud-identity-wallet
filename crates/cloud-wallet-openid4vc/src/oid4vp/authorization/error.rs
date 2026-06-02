//! OAuth and OpenID4VP authorization error codes.
//!
//! These error codes are used in authorization error responses as defined in
//! Section 8.5 of the OpenID4VP specification and follow the OAuth 2.0 error
//! response format.

use serde::Serialize;

/// OAuth and OpenID4VP authorization error codes used by Section 8.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorCode {
    /// The request is missing a required parameter, includes an invalid
    /// parameter value, or is otherwise malformed.
    InvalidRequest,

    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,

    /// Client authentication failed.
    InvalidClient,

    /// The resource owner or authorization server denied the request.
    AccessDenied,

    /// The authenticated client is not authorized to use this authorization
    /// grant type.
    UnauthorizedClient,

    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    UnsupportedResponseType,

    /// The authorization server encountered an unexpected condition that
    /// prevented it from completing the request.
    ServerError,

    /// The authorization server is currently unable to handle the request
    /// due to a temporary overloading or maintenance of the server.
    TemporarilyUnavailable,

    /// The Wallet does not support any of the requested VP formats.
    VpFormatsNotSupported,

    /// The Wallet does not support the request_uri method used in the
    /// authorization request.
    InvalidRequestUriMethod,

    /// The transaction data is invalid.
    InvalidTransactionData,

    /// The Wallet is currently unavailable to process the request.
    WalletUnavailable,
}
