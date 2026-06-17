//! Client identifier prefix handling for OpenID4VP.
//!
//! Each prefix defines how the Wallet obtains verifier metadata and keys:
//! - `redirect_uri:`: Metadata passed inline via `client_metadata` (unsigned requests only)
//! - `x509_*`: Key resolution via X.509 certificates

pub mod redirect_uri;
pub mod x509;
