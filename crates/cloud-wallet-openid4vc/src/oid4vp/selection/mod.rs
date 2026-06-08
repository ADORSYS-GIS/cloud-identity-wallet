//! Credential matching and selection engine for OID4VP.
//!
//! Implements the Wallet-side logic described in [OpenID4VP §6.4] for matching
//! stored credentials against a DCQL query and selecting which credentials and
//! claims to present to the Verifier.
//!
//! # Usage
//!
//! ```ignore
//! use cloud_wallet_openid4vc::oid4vp::selection::*;
//!
//! let query: DcqlQuery = /* parsed from authorization request */;
//! let credentials: Vec<CredentialView> = /* loaded from wallet store */;
//!
//! let result = match_dcql_query(&query, &credentials);
//! if result.is_satisfied() {
//!     let selected = result.select();
//!     // build VP token from `selected`
//! }
//! ```
//!
//! [OpenID4VP §6.4]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4

mod matching;
#[cfg(test)]
mod tests;

pub use matching::*;
