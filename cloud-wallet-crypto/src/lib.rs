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

pub mod aead;
pub mod digest;
pub mod ecdsa;
pub mod ed25519;
pub mod error;
#[cfg_attr(docsrs, doc(cfg(feature = "jwk")))]
#[cfg(feature = "jwk")]
pub mod jwk;
pub mod rand;
pub mod rsa;
pub mod secret;
mod utils;

// Public re-exports
pub use error::Error;
