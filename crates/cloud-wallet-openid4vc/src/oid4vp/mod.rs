//! OpenID4VP (OpenID for Verifiable Presentations) implementation.
//!
//! This module implements the OpenID4VP specification for verifiable presentations,
//! enabling the Wallet to respond to presentation requests from Verifiers.

pub mod authorization;
pub mod client_id;
pub mod dcql;
pub mod error;
pub mod metadata;
pub mod request_object;

pub use error::*;
pub use request_object::*;
