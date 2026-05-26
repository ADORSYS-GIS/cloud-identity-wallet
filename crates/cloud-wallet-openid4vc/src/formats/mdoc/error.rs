//! Error types for mDoc (ISO 18013-5) parsing.

use thiserror::Error;

/// A specialised [`Result`] type for mDoc parsing operations.
pub type Result<T> = std::result::Result<T, MdocError>;

/// Errors that can occur while parsing an [`IssuerSigned`] mDoc document.
///
/// [`IssuerSigned`]: crate::formats::mdoc::parse_issuer_signed
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MdocError {
    /// The input string is not valid unpadded base64url.
    #[error("invalid base64url encoding")]
    InvalidBase64 {
        /// Underlying decode error.
        #[source]
        source: base64ct::Error,
    },

    /// The decoded bytes are not valid CBOR.
    #[error("malformed CBOR")]
    CborDecode {
        /// Underlying CBOR parse error.
        #[source]
        source: ciborium::de::Error<std::io::Error>,
    },

    /// A required field is absent from the CBOR map.
    #[error("missing required CBOR field: '{0}'")]
    MissingField(&'static str),

    /// A field is present but has an unexpected CBOR type.
    #[error("unexpected CBOR type for field '{field}'")]
    UnexpectedCborType {
        /// Name of the offending field.
        field: &'static str,
    },

    /// The `issuerAuth` value could not be decoded as a COSE_Sign1 structure.
    #[error("failed to parse COSE_Sign1 structure: {reason}")]
    InvalidCoseSign1 {
        /// Human-readable description of the failure.
        reason: String,
    },

    /// The COSE_Sign1 has a detached payload; an inline payload is required for mDoc.
    #[error("COSE_Sign1 has a detached payload; an embedded payload is required")]
    MissingCosePayload,

    /// A `ciborium::Value` could not be serialised back to CBOR bytes.
    #[error("CBOR serialisation failed: {reason}")]
    CborEncode {
        /// Serialiser error message.
        reason: String,
    },

    /// The credential's validity period has ended.
    ///
    /// The `valid_until` field contains the RFC 3339 timestamp from the MSO
    /// `validityInfo.validUntil` field. Callers that cache `ParsedMdoc` values
    /// should re-check temporal validity against the stored timestamps before use.
    #[error("credential has expired (valid_until: {valid_until})")]
    ExpiredCredential {
        /// The `validUntil` timestamp from the MSO, in RFC 3339 form.
        valid_until: String,
    },

    /// The credential's validity period has not yet started.
    ///
    /// The `valid_from` field contains the RFC 3339 timestamp from the MSO
    /// `validityInfo.validFrom` field.
    #[error("credential is not yet valid (valid_from: {valid_from})")]
    NotYetValid {
        /// The `validFrom` timestamp from the MSO, in RFC 3339 form.
        valid_from: String,
    },
}
