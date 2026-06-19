//! OpenID4VP (OpenID for Verifiable Presentations) implementation.
//!
//! This module implements the OpenID4VP specification for verifiable presentations,
//! enabling the Wallet to respond to presentation requests from Verifiers.

pub mod authorization;
pub mod client;
pub mod client_id;
pub mod dcql;
pub mod error;
pub mod key_resolution;
pub mod metadata;
pub mod presentation;
pub mod request_object;
pub mod response_mode;
pub mod selection;
pub mod transaction_data;
pub mod verifier_attestation;

pub use error::*;

/// Converts a `cloud_wallet_crypto::jwk::Jwk` to a `jsonwebtoken::DecodingKey`.
///
/// This is shared between `verifier_attestation` and `key_resolution` to avoid
/// duplicating the serde conversion logic.
pub(crate) fn jwk_to_decoding_key(
    jwk: &cloud_wallet_crypto::jwk::Jwk,
) -> Result<jsonwebtoken::DecodingKey, String> {
    use jsonwebtoken::jwk::Jwk as JwtJwk;

    let jwt_jwk = serde_json::to_value(jwk)
        .and_then(serde_json::from_value::<JwtJwk>)
        .map_err(|e| format!("failed to convert JWK: {e}"))?;

    jsonwebtoken::DecodingKey::from_jwk(&jwt_jwk)
        .map_err(|e| format!("failed to create decoding key from JWK: {e}"))
}
