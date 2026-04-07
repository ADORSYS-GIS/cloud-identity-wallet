//! Format adapters for encoding and decoding [`Credential`] values.
//!
//! The [`CredentialFormat`] trait defines the contract for converting between
//! the wallet's canonical [`Credential`] representation and a specific wire
//! format. Format-specific adapters implement this trait.

use super::canonical::Credential;
use crate::errors::Error;

/// Options controlling how a [`Credential`] is encoded into a wire format.
#[derive(Debug, Clone, Default)]
pub struct EncodeOptions {}

/// A format adapter that can encode and decode credentials in a specific format.
pub trait CredentialFormat {
    /// The wire representation produced and consumed by this format.
    type Encoded;

    /// Encodes a [`Credential`] into this format's wire representation.
    fn encode(credential: &Credential, options: &EncodeOptions) -> Result<Self::Encoded, Error>;

    /// Decodes a wire token into the wallet's canonical [`Credential`].
    fn decode(encoded: &Self::Encoded) -> Result<Credential, Error>;
}
