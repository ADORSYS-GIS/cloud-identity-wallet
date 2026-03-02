//! The error type for cryptographic operations.

use std::error::Error as StdError;
use std::fmt;

use color_eyre::eyre::{Report, eyre};
use thiserror::Error;

/// The result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Represents an error that can occur during cryptographic operations.
#[derive(Error)]
pub struct Error {
    kind: ErrorKind,
    #[source]
    source: Option<Report>,
}

impl Error {
    /// Creates a new crypto error from a known kind and an arbitrary error.
    ///
    /// This can be used to wrap any error type into a cryptographic error.
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::{Error, ErrorKind};
    ///
    /// #[derive(Debug)]
    /// struct MyError(&'static str);
    ///
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "{}", self.0)
    ///     }
    /// }
    ///
    /// impl std::error::Error for MyError {}
    ///
    /// let custom_err = MyError("Something went wrong");
    ///
    /// let error = Error::new(ErrorKind::Other, custom_err);
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

    /// Creates a new crypto error from an arbitrary error.
    ///
    /// This is a convenience method for creating an error with [`ErrorKind::Other`].
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::Error;
    ///
    /// #[derive(Debug)]
    /// struct MyError(&'static str);
    ///
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "{}", self.0)
    ///     }
    /// }
    ///
    /// impl std::error::Error for MyError {}
    ///
    /// let custom_err = MyError("Something went wrong");
    ///
    /// let error = Error::other(custom_err);
    /// ```
    pub fn other<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::new(ErrorKind::Other, error)
    }

    /// Creates a new crypto error from a known kind and an error message.
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::{Error, ErrorKind};
    ///
    /// let error = Error::message(ErrorKind::Other, "Something went wrong");
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

    /// Returns the category of the error that occurred.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the reference to the underlying error, if any.
    ///
    /// If this error was constructed via [`new`] or [`other`],
    /// this method will return [`Some`], otherwise [`None`].
    ///
    /// [`new`]: Error::new
    /// [`other`]: Error::other
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::Error;
    ///
    /// #[derive(Debug)]
    /// struct MyError(&'static str);
    ///
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "{}", self.0)
    ///     }
    /// }
    ///
    /// impl std::error::Error for MyError {}
    ///
    /// let custom_err = MyError("Something went wrong");
    ///
    /// let error = Error::other(custom_err);
    /// assert!(error.get_source().is_some());
    /// ```
    pub fn get_source(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        self.source.as_ref().map(|e| e.as_ref())
    }

    /// Consumes this [`struct@Error`] and returns the inner error, if any.
    ///
    /// If this error was constructed via [`new`] or [`other`],
    /// this method will return [`Some`], otherwise [`None`].
    ///
    /// [`new`]: Error::new
    /// [`other`]: Error::other
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::Error;
    ///
    /// #[derive(Debug)]
    /// struct MyError(&'static str);
    ///
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "{}", self.0)
    ///     }
    /// }
    ///
    /// impl std::error::Error for MyError {}
    ///
    /// let custom_err = MyError("Something went wrong");
    ///
    /// let error = Error::other(custom_err);
    /// assert_eq!(error.into_inner().unwrap().to_string(), "Something went wrong");
    /// ```
    pub fn into_inner(self) -> Option<Box<dyn StdError + Send + Sync>> {
        self.source.map(|e| e.into())
    }

    /// Attempts to downcast the error to `E`.
    ///
    /// If this error contains a custom error,
    /// it will attempt downcasting on the inner error,
    /// otherwise it will return [`struct@Error`].
    ///
    /// # Example
    ///
    /// ```
    /// use cloud_wallet_crypto::error::Error;
    ///
    /// #[derive(Debug)]
    /// struct MyError(&'static str);
    ///
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "{}", self.0)
    ///     }
    /// }
    ///
    /// impl std::error::Error for MyError {}
    ///
    /// let custom_err = MyError("Something went wrong");
    ///
    /// let error = Error::other(custom_err);
    /// assert!(error.downcast::<MyError>().is_ok());
    /// ```
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

/// A category of error that can occur.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error that occurred while generating random bytes.
    #[error("Failed to generate random bytes")]
    RandomGeneration,

    /// An error that occurred while generating a key.
    #[error("Failed to generate key")]
    KeyGeneration,

    /// An error that occurred while parsing a key.
    #[error("Failed to parse key")]
    KeyParsing,

    /// The algorithm is not supported.
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The length of the data is insufficient
    #[error("The length is insufficient")]
    WrongLength,

    /// Error related to signature operations.
    #[error("Signature error")]
    Signature,

    /// Error related to encryption operations.
    #[error("Encryption error")]
    Encryption,

    /// Error related to decryption operations.
    #[error("Decryption error")]
    Decryption,

    /// Error related to serialization.
    #[error("Serialization error")]
    Serialization,

    /// An error that doesn't fit into any other error kind.
    #[error("Other error")]
    Other,
}
