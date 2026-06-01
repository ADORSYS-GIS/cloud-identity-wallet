//! Error types for mDoc (ISO 18013-5) parsing.

use thiserror::Error;

/// A specialised [`Result`] type for mDoc parsing operations.
pub type Result<T> = std::result::Result<T, MdocError>;

/// Errors that can occur while parsing an [`IssuerSigned`] mDoc document.
///
/// [`IssuerSigned`]: crate::formats::mdoc::ParsedMdoc::parse
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
    #[error("missing required CBOR field: '{field}'")]
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },

    /// A field is present but has an unexpected CBOR type.
    #[error("unexpected CBOR type for field '{field}'")]
    UnexpectedCborType {
        /// Name of the offending field.
        field: &'static str,
    },

    /// The `issuerAuth` value could not be decoded as a COSE_Sign1 structure.
    #[error("failed to parse COSE_Sign1 structure")]
    InvalidCoseSign1 {
        /// Underlying coset decode error.
        #[source]
        source: coset::CoseError,
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

    /// A CBOR map contains the same text key more than once.
    ///
    /// RFC 8949 §5.6 requires implementations to reject duplicate keys in
    /// security-sensitive contexts; duplicate keys can hide a second value
    /// behind a valid first one (e.g. `validUntil`, `digestID`).
    #[error("duplicate CBOR map key: '{key}'")]
    DuplicateMapKey {
        /// The duplicated key name.
        key: &'static str,
    },

    /// The MSO `digestAlgorithm` field names an algorithm this implementation
    /// does not support.
    ///
    /// ISO 18013-5 §9.1.2.5 permits `"SHA-256"`, `"SHA-384"`, and `"SHA-512"`;
    /// any other value must be rejected at parse time.
    #[error("unsupported digest algorithm: {algorithm}")]
    UnsupportedDigestAlgorithm {
        /// The algorithm name as it appeared in the MSO.
        algorithm: String,
    },

    /// The MSO `version` field uses a major version this implementation does not
    /// support.
    ///
    /// ISO 18013-5 §9.1.2.4 defines `"1.0"` as the current value. Per §8.1,
    /// a reader shall not error on an unknown *minor* version but must reject
    /// an unknown *major* version.
    #[error("unsupported MSO version: {version}")]
    UnsupportedMsoVersion {
        /// The version string as it appeared in the MSO.
        version: String,
    },

    /// A digest in `valueDigests` has the wrong byte length for the declared
    /// `digestAlgorithm`.
    ///
    /// ISO 18013-5 §9.1.2.5: the length of each digest value must match the
    /// output size of the named hash function (SHA-256 → 32, SHA-384 → 48,
    /// SHA-512 → 64 bytes).
    #[error(
        "digest length mismatch in namespace '{namespace}' for digestID {digest_id}: \
         expected {expected} bytes for {algorithm}, got {actual}"
    )]
    InvalidDigestLength {
        /// Namespace containing the offending entry.
        namespace: String,
        /// The digest identifier that has the wrong length.
        digest_id: u64,
        /// The declared hash algorithm.
        algorithm: String,
        /// Expected byte length for that algorithm.
        expected: usize,
        /// Actual byte length found in the CBOR value.
        actual: usize,
    },

    /// The computed hash of an `IssuerSignedItem` does not match the corresponding entry in
    /// the MSO `valueDigests` map (ISO/IEC 18013-5 §9.1.2).
    #[error("digest mismatch for namespace '{namespace}', digestID {digest_id}")]
    DigestMismatch {
        /// The mDoc namespace containing the offending item.
        namespace: String,
        /// The `digestID` of the offending item.
        digest_id: u64,
    },

    /// The MSO `valueDigests` map has no entry for a presented `IssuerSignedItem`.
    ///
    /// Every presented item must have a corresponding digest in the MSO; absence is treated
    /// as a verification failure (ISO/IEC 18013-5 §9.1.2).
    #[error("missing digest for namespace '{namespace}', digestID {digest_id}")]
    MissingDigest {
        /// The mDoc namespace containing the unverifiable item.
        namespace: String,
        /// The `digestID` that has no corresponding entry in `valueDigests`.
        digest_id: u64,
    },

    /// A `digestID` value exceeds the allowed range.
    ///
    /// ISO 18013-5 §9.1.2.4 requires that `digestID` values are smaller than 2^31.
    /// Values at or above this threshold are rejected at parse time.
    #[error("digestID {digest_id} out of range: must be less than 2^31")]
    DigestIdOutOfRange {
        /// The out-of-range value as parsed from the CBOR integer.
        digest_id: u64,
    },

    /// The MSO `validityInfo` timestamps violate the ordering constraints
    /// required by ISO 18013-5 §9.1.2.4:
    /// `validFrom` must be >= `signed`, and `validUntil` must be > `validFrom`.
    #[error("MSO validityInfo has invalid timestamp ordering")]
    InvalidValidityInfo,

    /// An `IssuerSignedItem` `random` field is shorter than the 16-byte minimum
    /// required by ISO 18013-5 §9.1.2.5.
    #[error("IssuerSignedItem random field is {actual} bytes; minimum is 16")]
    InvalidRandomLength {
        /// Actual byte length found.
        actual: usize,
    },
}
