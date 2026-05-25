use std::str::FromStr;

use cloud_wallet_crypto::digest::HashAlg;
use serde::{Deserialize, Serialize};

use crate::formats::sd_jwt::{Error, ProcessingError};

/// Supported IANA Named Information Hash Algorithm Registry.
/// See [Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml#hash-algorithm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IanaHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl IanaHashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }
}

impl std::fmt::Display for IanaHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<IanaHashAlgorithm> for HashAlg {
    fn from(value: IanaHashAlgorithm) -> Self {
        match value {
            IanaHashAlgorithm::Sha256 => HashAlg::Sha256,
            IanaHashAlgorithm::Sha384 => HashAlg::Sha384,
            IanaHashAlgorithm::Sha512 => HashAlg::Sha512,
            IanaHashAlgorithm::Sha3_256 => HashAlg::Sha3_256,
            IanaHashAlgorithm::Sha3_384 => HashAlg::Sha3_384,
            IanaHashAlgorithm::Sha3_512 => HashAlg::Sha3_512,
        }
    }
}

impl FromStr for IanaHashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha-256" => Ok(Self::Sha256),
            "sha-384" => Ok(Self::Sha384),
            "sha-512" => Ok(Self::Sha512),
            "sha3-256" => Ok(Self::Sha3_256),
            "sha3-384" => Ok(Self::Sha3_384),
            "sha3-512" => Ok(Self::Sha3_512),
            _ => Err(Error::DisclosureProcessing {
                reason: ProcessingError::UnsupportedHashAlgorithm(s.to_owned()),
            }),
        }
    }
}
