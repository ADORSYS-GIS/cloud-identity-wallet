//! Error types for the `cloud-wallet-openid4vc` crate.

use std::error::Error as StdError;
use std::fmt;

use color_eyre::eyre::{Report, eyre};
use thiserror::Error;

/// Error returned when attempting to create an empty [`ClaimPathPointer`].
///
/// [`ClaimPathPointer`]: crate::issuance::claim_path_pointer::ClaimPathPointer
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Error)]
#[error("claims path pointer must be non-empty")]
pub struct EmptyClaimPathError;

/// A specialised [`Result`] type for this crate.
///
/// [`Result`]: std::result::Result
pub type Result<T> = std::result::Result<T, Error>;

/// Represents an error that can occur within the OpenID4VCI credential domain.
///
/// Errors carry a machine-matchable [`ErrorKind`] for control flow and an optional
/// chained [`source`] for human-readable detail. Use [`Error::kind`] to branch on
/// the category; use the `Display` impl or the source chain for diagnostics.
///
/// [`source`]: Error::get_source
#[derive(Error)]
pub struct Error {
    kind: ErrorKind,
    #[source]
    source: Option<Report>,
}

impl Error {
    /// Creates a new error from a known kind and an arbitrary underlying error.
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_openid4vc::errors::{Error, ErrorKind};
    ///
    /// let io_err = std::io::Error::other("disk full");
    /// let err = Error::new(ErrorKind::Other, io_err);
    /// assert_eq!(err.kind(), ErrorKind::Other);
    /// ```
    pub fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            kind,
            source: Some(Report::new(error)),
        }
    }

    /// Creates an error with [`ErrorKind::Other`] wrapping an arbitrary error.
    pub fn other<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Other, error)
    }

    /// Creates an error from a known kind and a plain message string.
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_openid4vc::errors::{Error, ErrorKind};
    ///
    /// let err = Error::message(ErrorKind::InvalidCredential, "issuer must not be blank");
    /// assert_eq!(err.kind(), ErrorKind::InvalidCredential);
    /// ```
    pub fn message<M>(kind: ErrorKind, msg: M) -> Self
    where
        M: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Self {
            kind,
            source: Some(eyre!(msg)),
        }
    }

    /// Returns the category of this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns a reference to the underlying source error, if any.
    pub fn get_source(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        self.source.as_ref().map(|e| e.as_ref())
    }

    /// Consumes this error and returns the inner source, if any.
    pub fn into_inner(self) -> Option<Box<dyn StdError + Send + Sync>> {
        self.source.map(|e| e.into())
    }

    /// Attempts to downcast the inner source error to `E`.
    pub fn downcast<E>(self) -> std::result::Result<E, Self>
    where
        E: StdError + Send + Sync + 'static,
    {
        let Error { kind, source } = self;
        match source {
            Some(e) => match e.downcast::<E>() {
                Ok(err) => Ok(err),
                Err(report) => Err(Error {
                    kind,
                    source: Some(report),
                }),
            },
            None => Err(Error { kind, source }),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kind: {}", self.kind)?;
        if let Some(source) = &self.source {
            write!(f, "\n\nCaused by:\n\t{source}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("Error");
        ds.field("kind", &self.kind);
        if let Some(source) = &self.source {
            ds.field("source", source);
        }
        ds.finish()
    }
}

/// The category of an `Error`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A credential failed structural validation (e.g. blank issuer, invalid dates).
    #[error("Invalid credential")]
    InvalidCredential,

    /// A credential offer failed validation or parsing.
    #[error("Invalid credential offer")]
    InvalidCredentialOffer,

    /// A credential request failed validation or parsing.
    #[error("Invalid credential request")]
    InvalidCredentialRequest,

    /// An authorization response returned by the Authorization Server failed
    /// validation or parsing (e.g. missing `code` parameter, duplicate
    /// recognized parameters, non-parseable redirect URI).
    ///
    /// Defined by [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2)
    /// and [OpenID4VCI §5.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-authorization-re).
    #[error("Invalid authorization response")]
    InvalidAuthorizationResponse,

    /// An operation was attempted on a credential that has been revoked.
    #[error("Credential is revoked")]
    CredentialRevoked,

    /// Authorization server metadata failed structural validation (e.g. missing required
    /// fields, `issuer` not using `https`, empty `response_types_supported`).
    ///
    /// Defined by [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).
    #[error("Invalid authorization server metadata")]
    InvalidAuthorizationServerMetadata,

    /// Credential Issuer Metadata failed structural validation.
    #[error("Invalid issuer metadata")]
    InvalidIssuerMetadata,

    /// A token request failed validation or parsing (e.g. missing required field for
    /// the specified grant type, conflicting parameters).
    ///
    /// Defined by [RFC 6749 §4.1.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3)
    /// and [OpenID4VCI §6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request).
    #[error("Invalid token request")]
    InvalidTokenRequest,

    /// A token response failed validation or parsing (e.g. missing `access_token`).
    ///
    /// Defined by [RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)
    /// and [OpenID4VCI §6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-successful-token-response).
    #[error("Invalid token response")]
    InvalidTokenResponse,

    /// An error that doesn't fit into any other category.
    #[error("Other error")]
    Other,
}
