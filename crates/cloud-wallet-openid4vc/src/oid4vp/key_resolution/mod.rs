//! Key resolution implementations for OpenID4VP client identifier prefixes.
//!
//! [`VerifierKeyResolver`]: crate::oid4vp::request_object::VerifierKeyResolver

pub mod error;
pub mod redirect_uri;

pub use error::RedirectUriKeyError;
