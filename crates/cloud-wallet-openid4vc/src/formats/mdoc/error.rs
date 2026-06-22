//! Error types for mDoc (ISO 18013-5) parsing and digest verification.

use thiserror::Error;

/// A specialised [`Result`] type for mDoc parsing operations.
pub type Result<T> = std::result::Result<T, MdocError>;

/// Errors that can occur while parsing or verifying an mDoc document.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MdocError {
    /// The input string is not valid unpadded base64url.
    #[error("invalid base64url encoding")]
    InvalidBase64 {
        #[source]
        source: base64ct::Error,
    },

    /// The decoded bytes are not valid CBOR.
    #[error("malformed CBOR")]
    CborDecode {
        #[source]
        source: ciborium::de::Error<std::io::Error>,
    },

    /// A required field is absent from the CBOR map.
    #[error("missing required CBOR field: '{field}'")]
    MissingField { field: &'static str },

    /// A field is present but has an unexpected CBOR type.
    #[error("unexpected CBOR type for field '{field}'")]
    UnexpectedCborType { field: &'static str },

    /// A `tdate` field contains a valid `#6.0(tstr)` structure but the string is not
    /// a valid RFC 3339 timestamp.
    #[error("malformed RFC 3339 timestamp for field '{field}': {value}")]
    MalformedTimestamp { field: &'static str, value: String },

    /// The `issuerAuth` value could not be decoded as a COSE_Sign1 structure.
    #[error("failed to parse COSE_Sign1 structure")]
    InvalidCoseSign1 {
        #[source]
        source: coset::CoseError,
    },

    /// The COSE_Sign1 has a detached payload; an inline payload is required for mDoc.
    #[error("COSE_Sign1 has a detached payload; an embedded payload is required")]
    MissingCosePayload,

    /// A `ciborium::Value` could not be serialised back to CBOR bytes.
    #[error("CBOR serialisation failed: {reason}")]
    CborEncode { reason: String },

    /// The credential's validity period has ended.
    #[error("credential has expired (valid_until: {valid_until})")]
    ExpiredCredential { valid_until: String },

    /// The credential's validity period has not yet started.
    #[error("credential is not yet valid (valid_from: {valid_from})")]
    NotYetValid { valid_from: String },

    /// A CBOR map contains the same text key more than once.
    #[error("duplicate CBOR map key: '{key}'")]
    DuplicateMapKey { key: &'static str },

    /// The MSO `digestAlgorithm` field names an algorithm this implementation does not support.
    #[error("unsupported digest algorithm: {algorithm}")]
    UnsupportedDigestAlgorithm { algorithm: String },

    /// The MSO `version` field uses a major version this implementation does not support.
    #[error("unsupported MSO version: {version}")]
    UnsupportedMsoVersion { version: String },

    /// A digest in `valueDigests` has the wrong byte length for the declared `digestAlgorithm`.
    #[error(
        "digest length mismatch in namespace '{namespace}' for digestID {digest_id}: \
         expected {expected} bytes for {algorithm}, got {actual}"
    )]
    InvalidDigestLength {
        namespace: String,
        digest_id: u64,
        algorithm: String,
        expected: usize,
        actual: usize,
    },

    /// The computed hash of an `IssuerSignedItem` does not match the MSO `valueDigests` entry.
    #[error("digest mismatch for namespace '{namespace}', digestID {digest_id}")]
    DigestMismatch { namespace: String, digest_id: u64 },

    /// The MSO `valueDigests` map has no entry for a presented `IssuerSignedItem`.
    #[error("missing digest for namespace '{namespace}', digestID {digest_id}")]
    MissingDigest { namespace: String, digest_id: u64 },

    /// A `digestID` value is out of the allowed range (ISO 18013-5 §9.1.2.4 requires < 2^31).
    #[error("digestID {digest_id} out of range: must be less than 2^31")]
    DigestIdOutOfRange { digest_id: i128 },

    /// The MSO `validityInfo` timestamps violate ordering constraints.
    #[error("MSO validityInfo has invalid timestamp ordering")]
    InvalidValidityInfo,

    /// An `IssuerSignedItem` `random` field is shorter than the 16-byte minimum.
    #[error("IssuerSignedItem random field is {actual} bytes; minimum is 16")]
    InvalidRandomLength { actual: usize },

    /// The COSE_Sign1 protected header is missing the algorithm field.
    #[error("COSE_Sign1 protected header is missing the algorithm field")]
    MissingAlgorithm,

    /// The COSE_Sign1 algorithm identifier is not supported for issuer signature verification.
    #[error("unsupported COSE signature algorithm: {alg}")]
    UnsupportedAlgorithm {
        /// The raw COSE algorithm integer label.
        alg: i64,
    },

    /// The `x5chain` header (COSE unprotected header label 33) is absent.
    #[error("x5chain (COSE header key 33) not found in unprotected header")]
    MissingX5Chain,

    /// The Document Signer Certificate does not carry the required Extended Key Usage OID.
    #[error("document signer certificate is missing required EKU OID 1.0.18013.5.1.2")]
    MissingDocSignerEku,

    /// The Document Signer Certificate is missing the `digitalSignature` key usage bit.
    #[error(
        "document signer certificate missing required digitalSignature key usage bit \
         (ISO 18013-5 Annex B Table B.3)"
    )]
    MissingDigitalSignatureKeyUsage,

    /// The Document Signer Certificate Key Usage extension is not marked critical.
    #[error(
        "document signer certificate Key Usage extension must be critical \
         (ISO 18013-5 Annex B Table B.3)"
    )]
    NonCriticalKeyUsage,

    /// The certificate chain could not be validated against a trusted IACA root.
    #[error("certificate chain validation failed: {reason}")]
    InvalidCertificateChain { reason: String },

    /// The COSE_Sign1 signature does not verify against the Document Signer Certificate.
    #[error("issuer signature verification failed")]
    InvalidIssuerSignature,

    /// DSC subject country code does not match the IACA root subject country.
    #[error(
        "country mismatch: DSC subject country '{dsc_country}' differs from IACA subject country '{iaca_country}'"
    )]
    CountryMismatch {
        dsc_country: String,
        iaca_country: String,
    },

    /// DSC subject stateOrProvinceName does not match the IACA root subject stateOrProvinceName.
    #[error(
        "state/province mismatch: DSC subject state '{dsc_state}' differs from IACA subject state '{iaca_state}'"
    )]
    StateMismatch {
        dsc_state: String,
        iaca_state: String,
    },

    /// MSO `validityInfo.signed` falls outside the Document Signer Certificate validity window.
    #[error("MSO signed at {signed_at} is outside DSC validity window [{not_before}, {not_after}]")]
    SignedOutsideDscValidity {
        /// Unix timestamp of `validityInfo.signed`.
        signed_at: i64,
        /// Unix timestamp of the DSC `notBefore`.
        not_before: i64,
        /// Unix timestamp of the DSC `notAfter`.
        not_after: i64,
    },

    /// MSO `docType` does not match the outer document `docType`.
    #[error("docType mismatch: MSO contains '{mso}' but outer document contains '{document}'")]
    DocTypeMismatch { mso: String, document: String },

    /// The `deviceKeyInfo.deviceKey` bytes could not be decoded as a valid COSE_Key.
    #[error("malformed COSE_Key in deviceKeyInfo: {reason}")]
    MalformedDeviceKey { reason: String },

    /// The COSE_Key `kty`/`crv` combination is not supported for device-key binding.
    #[error("unsupported device key type or curve: {reason}")]
    UnsupportedDeviceKeyType { reason: &'static str },

    /// The curve in the COSE_Key does not match the curve in the proof JWK.
    #[error("device key curve mismatch: COSE key uses {cose_crv}, proof JWK uses {jwk_crv}")]
    CurveMismatch { cose_crv: String, jwk_crv: String },

    /// The public key in the MSO `deviceKeyInfo` does not match the holder's proof JWK.
    #[error("MSO device key does not match proof JWK")]
    DeviceKeyMismatch,
}
