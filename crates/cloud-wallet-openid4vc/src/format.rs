//! Format adapters for encoding and decoding [`Credential`] values.
//!
//! The [`CredentialFormat`] trait defines the contract for converting between
//! the wallet's canonical [`Credential`] representation and a specific wire
//! format. Each adapter type implements this trait for one format.
//!
//! # Design
//!
//! The wallet's [`Credential`] type is encoding-agnostic. It is produced by
//! calling [`CredentialFormat::decode`] on a received token and stored as-is.
//! When a credential needs to be presented, [`CredentialFormat::encode`] is
//! called to produce the appropriate wire token.
//!
//! Format adapters are zero-sized types. All state required for encoding or
//! decoding is passed through the method arguments.
//!
//! # Status
//!
//! The three adapters below are scaffolding. Their `encode` and `decode`
//! implementations are left as `todo!()` pending integration with format-specific
//! crates (e.g. `sd-jwt-vc`, `isomdoc`). The trait and adapter types are
//! provided now so that call sites can be written against the stable API.

use crate::errors::Error;
use crate::models::Credential;

// ── EncodeOptions ─────────────────────────────────────────────────────────────

/// Options controlling how a [`Credential`] is encoded into a wire format.
///
/// Currently empty. Future additions will include selective disclosure
/// configuration for SD-JWT, presentation context, and holder binding options.
#[derive(Debug, Clone, Default)]
pub struct EncodeOptions {
    // Selective disclosure configuration, presentation context, etc. — TBD.
}

// ── CredentialFormat ──────────────────────────────────────────────────────────

/// A format adapter that can encode and decode credentials in a specific format.
///
/// Implementors are zero-sized types (unit structs). All encoding/decoding state
/// is carried through method arguments.
///
/// # Example
///
/// ```rust,ignore
/// let token: String = SdJwtFormat::decode("eyJ...", &Default::default())?;
/// let encoded: String = SdJwtFormat::encode(&credential, &Default::default())?;
/// ```
pub trait CredentialFormat {
    /// The wire representation produced and consumed by this format.
    ///
    /// `String` for text-based formats (SD-JWT VC, W3C VC JWT).
    /// `Vec<u8>` for binary formats (mdoc CBOR).
    type Encoded;

    /// Encodes a [`Credential`] into this format's wire representation.
    fn encode(credential: &Credential, options: &EncodeOptions) -> Result<Self::Encoded, Error>;

    /// Decodes a wire token into the wallet's canonical [`Credential`].
    fn decode(encoded: &Self::Encoded) -> Result<Credential, Error>;
}

// ── SdJwtFormat ───────────────────────────────────────────────────────────────

/// Format adapter for the IETF SD-JWT VC format (`dc+sd-jwt`).
///
/// The wire representation is a compact string of the form
/// `<Issuer-JWT>~<Disclosure>*~[<KB-JWT>]`.
///
/// Spec: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3>
pub struct SdJwtFormat;

impl CredentialFormat for SdJwtFormat {
    type Encoded = String;

    fn encode(credential: &Credential, _options: &EncodeOptions) -> Result<String, Error> {
        // TODO: integrate `sd-jwt-vc` crate — generate issuer JWT + disclosures.
        let _ = credential;
        todo!("SD-JWT VC encoding is not yet implemented")
    }

    fn decode(encoded: &String) -> Result<Credential, Error> {
        // TODO: integrate `sd-jwt-vc` crate — verify issuer JWT, reconstruct claims
        // from disclosures, extract `vct`, `iss`, `sub`, `iat`, `exp`, `status`.
        let _ = encoded;
        todo!("SD-JWT VC decoding is not yet implemented")
    }
}

// ── JwtVcJsonFormat ───────────────────────────────────────────────────────────

/// Format adapter for the W3C VC Data Model secured as a JWT (`jwt_vc_json`).
///
/// The wire representation is a compact JWT string.
///
/// Spec: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3>
pub struct JwtVcJsonFormat;

impl CredentialFormat for JwtVcJsonFormat {
    type Encoded = String;

    fn encode(credential: &Credential, _options: &EncodeOptions) -> Result<String, Error> {
        // TODO: build W3C VC payload and sign as a JWT.
        let _ = credential;
        todo!("W3C VC JWT encoding is not yet implemented")
    }

    fn decode(encoded: &String) -> Result<Credential, Error> {
        // TODO: verify JWT, extract `credentialSubject`, `issuer`, `type`, validity period.
        let _ = encoded;
        todo!("W3C VC JWT decoding is not yet implemented")
    }
}

// ── MsoMdocFormat ─────────────────────────────────────────────────────────────

/// Format adapter for the ISO/IEC 18013-5 mdoc format (`mso_mdoc`).
///
/// The wire representation is a CBOR-encoded byte string.
///
/// Spec: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2>
pub struct MsoMdocFormat;

impl CredentialFormat for MsoMdocFormat {
    /// mdoc wire encoding is CBOR — represented here as a byte vector.
    type Encoded = Vec<u8>;

    fn encode(credential: &Credential, _options: &EncodeOptions) -> Result<Vec<u8>, Error> {
        // TODO: integrate `isomdoc` or equivalent crate — build IssuerSigned CBOR structure.
        let _ = credential;
        todo!("mdoc encoding is not yet implemented")
    }

    fn decode(encoded: &Vec<u8>) -> Result<Credential, Error> {
        // TODO: integrate `isomdoc` — parse MSO, verify issuer signature, flatten namespaces.
        let _ = encoded;
        todo!("mdoc decoding is not yet implemented")
    }
}
