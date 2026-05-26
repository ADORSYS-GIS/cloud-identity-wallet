/// Errors returned while parsing an SD-JWT VC or one of its embedded parts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The compact SD-JWT string did not contain the expected `~` separator.
    #[error("SD-JWT must contain at least one '~' separator")]
    MissingSdJwtSeparator,

    /// The issued SD-JWT serialization is missing the trailing `~`.
    #[error("issued SD-JWT without key binding must end with '~'")]
    MissingSdJwtTrailingSeparator,

    /// The issuer-signed JWT component is missing.
    #[error("SD-JWT issuer-signed JWT is missing")]
    MissingIssuerJwt,

    /// A compact JWT component did not contain exactly three non-empty JWS parts.
    #[error("{component} must be a compact JWS with three non-empty parts")]
    InvalidJwtCompact {
        /// Human-readable component name.
        component: &'static str,
    },

    /// The JOSE header uses the unsecured `none` algorithm.
    #[error("{component} uses the unsecured 'none' algorithm")]
    UnsecuredJwt {
        /// Human-readable component name.
        component: &'static str,
    },

    /// JWT header or claim decoding failed.
    #[error("failed to decode {component}")]
    JwtDecoding {
        /// Human-readable component name.
        component: &'static str,
        /// Underlying JWT decoding error.
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    /// A JWT component failed SD-JWT VC profile validation.
    #[error("invalid {component}: {reason}")]
    InvalidJwtProfile {
        /// Human-readable component name.
        component: &'static str,
        /// Profile validation failure.
        reason: &'static str,
    },

    /// A disclosure could not be parsed.
    #[error("invalid disclosure at index {index}: {source}")]
    InvalidDisclosure {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
        /// Underlying disclosure parse failure.
        #[source]
        source: DisclosureError,
    },

    /// The SD-JWT disclosure processing rules failed.
    #[error("disclosure processing failed: {reason}")]
    DisclosureProcessing {
        /// Processing failure reason.
        reason: ProcessingError,
    },
}

/// Failures that can occur while parsing an individual Disclosure.
#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    /// The disclosure component is empty.
    #[error("empty disclosure")]
    Empty,

    /// The disclosure is not valid unpadded base64url.
    #[error("not valid base64url")]
    Base64(#[source] base64::DecodeError),

    /// The disclosure decoded to invalid JSON.
    #[error("not valid JSON")]
    Json(#[source] serde_json::Error),

    /// The disclosure JSON value was not the expected two- or three-element array.
    #[error("must be a two- or three-element array")]
    InvalidShape,

    /// A disclosure salt or claim name had the wrong JSON type.
    #[error("invalid {field}")]
    InvalidField {
        /// Field name.
        field: &'static str,
    },
}

/// Failure reason for RFC 9901 disclosure processing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProcessingError {
    /// The `_sd_alg` claim names a hash algorithm this crate does not support.
    #[error("unsupported _sd_alg '{0}'")]
    UnsupportedHashAlgorithm(String),

    /// A disclosure digest appeared more than once in the input disclosure list.
    #[error("duplicate disclosure digest '{0}'")]
    DuplicateDigest(String),

    /// An `_sd` claim was present but was not an array of strings.
    #[error("_sd must be an array of strings")]
    InvalidSdClaim,

    /// The SD-JWT payload is not valid JSON.
    #[error("not valid JSON")]
    Json(String),

    /// A digest value was encountered more than once in the payload tree.
    #[error("digest '{0}' is embedded more than once")]
    DuplicateEmbeddedDigest(String),

    /// A digest in an object `_sd` array referenced an array-element disclosure.
    #[error("object disclosure expected for digest '{0}'")]
    ExpectedObjectDisclosure(String),

    /// A digest in an array element referenced an object-property disclosure.
    #[error("array-element disclosure expected for digest '{0}'")]
    ExpectedArrayDisclosure(String),

    /// An object disclosure attempted to disclose a reserved claim name.
    #[error("reserved disclosed claim name '{0}'")]
    ReservedClaimName(String),

    /// An object disclosure attempted to overwrite an existing claim.
    #[error("disclosed claim '{0}' already exists")]
    DuplicateClaimName(String),

    /// A supplied Disclosure was not referenced by the payload tree.
    #[error("disclosure digest '{0}' was not referenced")]
    UnreferencedDisclosure(String),

    /// The payload nesting is too deep to process safely.
    #[error("payload nesting exceeds maximum supported depth of {0}")]
    MaxDepthExceeded(usize),
}
