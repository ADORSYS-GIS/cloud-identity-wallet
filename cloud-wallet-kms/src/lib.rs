#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![deny(unused_must_use)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod cache;
pub mod nonce;
pub mod provider;
pub mod storage;

mod key;
mod utils;

// Public re-exports
pub use key::dek::{DataEncryptionKey, Id as DekId};
pub use key::master::{Id as MasterId, Metadata};

use cloud_wallet_crypto::aead::Algorithm;
use color_eyre::eyre::Report;

/// The result type for KMS operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Represents an error that can occur during KMS operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error originating from the storage backend.
    #[error("Storage error")]
    Storage(#[source] Report),

    /// An error originating from the KMS provider.
    #[error("Provider error")]
    Provider(#[source] Report),

    /// An error related to cryptographic operations.
    #[error("Crypto error")]
    Crypto(#[source] Report),

    /// An unspecified or other error.
    #[error("Other error: {0}")]
    Other(String),
}

impl From<cloud_wallet_crypto::Error> for crate::Error {
    fn from(error: cloud_wallet_crypto::Error) -> Self {
        crate::Error::Crypto(error.into())
    }
}

/// AEAD encryption algorithm
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AeadAlgorithm(pub Algorithm);

impl From<Algorithm> for AeadAlgorithm {
    fn from(alg: Algorithm) -> Self {
        Self(alg)
    }
}

impl From<AeadAlgorithm> for Algorithm {
    fn from(aead_alg: AeadAlgorithm) -> Self {
        aead_alg.0
    }
}

impl std::fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AeadAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "AES-128-GCM" => Ok(AeadAlgorithm(Algorithm::AesGcm128)),
            "AES-256-GCM" => Ok(AeadAlgorithm(Algorithm::AesGcm256)),
            "ChaCha20-Poly1305" => Ok(AeadAlgorithm(Algorithm::ChaCha20Poly1305)),
            _ => Err(Error::Other(format!("Invalid algorithm: {s}"))),
        }
    }
}
