//! OpenID4VP (OpenID for Verifiable Presentations) implementation.
//!
//! This module implements the OpenID4VP specification for verifiable presentations,
//! enabling the Wallet to respond to presentation requests from Verifiers.

pub mod authorization;
pub mod client_id;
pub mod dcql;
pub mod formats;
pub mod error;
pub mod metadata;
pub mod presentation;
pub mod request_object;
pub mod selection;
pub mod transaction_data;
pub mod verifier_attestation;

pub use error::*;
