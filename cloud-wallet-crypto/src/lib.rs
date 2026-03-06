#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod aead;
pub mod digest;
pub mod ecdsa;
pub mod ed25519;
pub mod error;
#[cfg(feature = "jwk")]
pub mod jwk;
pub mod rand;
pub mod rsa;
pub mod secret;
mod utils;

// Public re-exports
pub use error::Error;
