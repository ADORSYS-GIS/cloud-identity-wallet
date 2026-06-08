//! Error types for mDoc (ISO 18013-5) parsing and digest verification.

use thiserror::Error;

/// A specialised [`Result`] type for mDoc parsing operations.
pub type Result<T> = std::result::Result<T, MdocError>;

/// Errors that can occur while parsing or verifying an mDoc document.
///
/// Returned by [`ParsedMdoc::parse`] and [`verify_digests`].
///
/// [`ParsedMdoc::parse`]: crate::formats::mdoc::ParsedMdoc::parse
/// [`verify_digests`]: crate::formats::mdoc::verifier::verify_digests
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
    /// security-sensitive contexts; a duplicate key could hide a second value
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

    /// The COSE_Sign1 protected header has no algorithm field, or the algorithm
    /// field is a text label rather than an integer.
    ///
    /// ISO 18013-5 §9.1.2 requires the algorithm to be present and to be one of
    /// the integer COSE algorithm identifiers.
    #[error("COSE_Sign1 protected header is missing the algorithm field")]
    MissingAlgorithm,

    /// The COSE_Sign1 algorithm identifier is not supported for issuer signature
    /// verification.
    ///
    /// Supported algorithm identifiers: -7 (ES256/P-256), -35 (ES384/P-384),
    /// -36 (ES512/P-521), -8 (EdDSA/Ed25519).
    #[error("unsupported COSE signature algorithm: {alg}")]
    UnsupportedAlgorithm {
        /// The raw COSE algorithm integer label.
        alg: i64,
    },

    /// The `x5chain` header (COSE unprotected header label 33) is absent.
    ///
    /// ISO 18013-5 §9.1.2 requires the issuer certificate chain to be conveyed
    /// in the `x5chain` header so the verifier can validate the signing certificate.
    #[error("x5chain (COSE header key 33) not found in unprotected header")]
    MissingX5Chain,

    /// The Document Signer Certificate (DSC) does not carry the required Extended Key
    /// Usage OID.
    ///
    /// ISO 18013-5 §9.1.2 mandates that every DSC includes OID 1.0.18013.5.1.2 in its
    /// Extended Key Usage extension.
    #[error("document signer certificate is missing required EKU OID 1.0.18013.5.1.2")]
    MissingDocSignerEku,

    /// The Document Signer Certificate does not have the `digitalSignature` key usage
    /// bit set, or its Key Usage extension is absent entirely.
    ///
    /// ISO 18013-5 Annex B Table B.3 requires every DSC to carry a critical Key Usage
    /// extension with (at least) the `digitalSignature` bit asserted.
    #[error(
        "document signer certificate missing required digitalSignature key usage bit \
         (ISO 18013-5 Annex B Table B.3)"
    )]
    MissingDigitalSignatureKeyUsage,

    /// The Document Signer Certificate has a Key Usage extension whose `digitalSignature`
    /// bit is set but the extension is not marked critical.
    ///
    /// ISO 18013-5 Annex B Table B.3 requires the Key Usage extension to be critical so
    /// that relying parties cannot ignore it. A non-critical extension is treated as a
    /// structural violation distinct from the extension being absent.
    #[error(
        "document signer certificate Key Usage extension must be critical \
         (ISO 18013-5 Annex B Table B.3)"
    )]
    NonCriticalKeyUsage,

    /// The certificate chain could not be validated against a trusted IACA root.
    ///
    /// This covers both structural chain errors (e.g. signature mismatch between
    /// consecutive certificates) and the absence of any trusted root for the chain.
    #[error("certificate chain validation failed: {reason}")]
    InvalidCertificateChain {
        /// Human-readable description of why validation failed.
        reason: String,
    },

    /// The COSE_Sign1 signature does not verify against the Document Signer Certificate.
    ///
    /// Returned when the cryptographic signature check (EC-DSA or EdDSA) fails after
    /// a valid certificate chain has already been established.
    #[error("issuer signature verification failed")]
    InvalidIssuerSignature,

    /// DSC subject country code does not match the IACA root subject country (ISO 18013-5 §9.3.3).
    ///
    /// Country consistency is checked between the Document Signer Certificate subject DN
    /// and the trust-store IACA root subject DN; both must carry the same ISO 3166-1
    /// alpha-2 `CountryName` attribute when the attribute is present in both certs.
    #[error(
        "country mismatch: DSC subject country '{dsc_country}' differs from IACA subject country '{iaca_country}'"
    )]
    CountryMismatch {
        /// Country code from the DSC's subject distinguished name.
        dsc_country: String,
        /// Country code from the IACA root's subject distinguished name.
        iaca_country: String,
    },

    /// DSC subject stateOrProvinceName does not match the IACA root subject stateOrProvinceName
    /// (ISO 18013-5 §9.3.3).
    ///
    /// When both the DSC and the trusted IACA root carry a `stateOrProvinceName` attribute in
    /// their subject DNs, the values must be equal.
    #[error(
        "state/province mismatch: DSC subject state '{dsc_state}' differs from IACA subject state '{iaca_state}'"
    )]
    StateMismatch {
        /// stateOrProvinceName from the DSC's subject distinguished name.
        dsc_state: String,
        /// stateOrProvinceName from the IACA root's subject distinguished name.
        iaca_state: String,
    },

    /// MSO `validityInfo.signed` falls outside the Document Signer Certificate validity
    /// window (ISO 18013-5 §9.3.1 step 5).
    ///
    /// The three timestamps are provided as Unix seconds for diagnostic logging.
    #[error("MSO signed at {signed_at} is outside DSC validity window [{not_before}, {not_after}]")]
    SignedOutsideDscValidity {
        /// The `validityInfo.signed` timestamp from the MSO, as a Unix second.
        signed_at: i64,
        /// The DSC `notBefore` timestamp, as a Unix second.
        not_before: i64,
        /// The DSC `notAfter` timestamp, as a Unix second.
        not_after: i64,
    },

    /// MSO `docType` does not match the outer document `docType` (ISO 18013-5 §9.3.1 step 4).
    ///
    /// The `docType` in the MSO payload must equal the `docType` in the enclosing document
    /// structure; a mismatch indicates the credential was prepared for a different document type.
    #[error("docType mismatch: MSO contains '{mso}' but outer document contains '{document}'")]
    DocTypeMismatch {
        /// The `docType` string as it appeared in the MSO.
        mso: String,
        /// The `docType` string from the outer document.
        document: String,
    },

    /// The CBOR bytes in `deviceKeyInfo.deviceKey` could not be decoded as a valid COSE_Key.
    ///
    /// Covers: the bytes are not valid CBOR; the top-level value is not a map; a required
    /// integer label (kty=1, crv=−1, x=−2, y=−3) is absent; or a label's value has the
    /// wrong CBOR type (e.g. x is not a bstr).
    ///
    /// ISO/IEC 18013-5 §9.1.2.4 — `DeviceKeyInfo.deviceKey` structure.
    /// RFC 8152 §13.1 — EC2 COSE_Key parameters.
    #[error("malformed COSE_Key in deviceKeyInfo: {reason}")]
    MalformedDeviceKey {
        /// Human-readable description of the structural defect.
        reason: String,
    },

    /// The COSE_Key `kty`/`crv` combination is not supported for device-key binding,
    /// or the proof JWK carries an incompatible key type.
    ///
    /// Specific cases that trigger this variant:
    /// - `kty` is not `2` (EC2) and not `1` (OKP).
    /// - `kty=2` (EC2) but `crv` is not P-256 (1), P-384 (2), or P-521 (3).
    /// - `kty=1` (OKP) but `crv` is not Ed25519 (6).
    /// - `kty=2` (EC2) and the `y` parameter is a `bool` (compressed EC2 point); direct
    ///   byte comparison requires the uncompressed form.
    /// - The proof JWK `key` variant is not `Key::Ec` or `Key::Okp { crv: Ed25519 }`.
    ///
    /// RFC 8152 §13.1 (EC2), §13.2 (OKP).
    /// ISO/IEC 18013-5 §9.1.5.2 Table 22 — permitted device-key curves.
    #[error("unsupported device key type or curve")]
    UnsupportedDeviceKeyType,

    /// The curve identified in the COSE_Key does not match the curve in the proof JWK.
    ///
    /// Both keys must name the same curve; a mismatch means the credential was issued
    /// for a different key type than the holder presented in their proof JWT.
    ///
    /// OID4VCI Appendix A.2 — holder binding via proof JWT.
    #[error("device key curve mismatch: COSE key uses {cose_crv}, proof JWK uses {jwk_crv}")]
    CurveMismatch {
        /// Curve name from the COSE_Key `crv` parameter (e.g. `"P-256"`).
        cose_crv: String,
        /// Curve name from the proof JWK (e.g. `"P-384"`).
        jwk_crv: String,
    },

    /// The public key embedded in the MSO `deviceKeyInfo` does not match the holder's
    /// proof JWK.
    ///
    /// Both keys parsed correctly and their curves agree, but the constant-time comparison
    /// of one or more coordinates (x, or x and y for EC2) failed. This indicates either a
    /// key-substitution attack by the issuer or a logic error — the credential must be
    /// rejected.
    ///
    /// Comparison is performed with `subtle::ConstantTimeEq` to prevent timing side channels.
    /// Which coordinate failed is intentionally not reported.
    ///
    /// ISO/IEC 18013-5 §9.1.2.4 — `DeviceKeyInfo.deviceKey`.
    /// OID4VCI Appendix A.2 — holder binding via proof JWT.
    #[error("MSO device key does not match proof JWK")]
    DeviceKeyMismatch,
}
