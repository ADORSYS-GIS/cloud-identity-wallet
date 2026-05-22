/// Errors returned while parsing an SD-JWT VC or one of its embedded parts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The compact SD-JWT string did not contain the expected `~` separator.
    #[error("SD-JWT must contain at least one '~' separator")]
    MissingSdJwtSeparator,

    /// The issuer-signed JWT component is missing.
    #[error("SD-JWT issuer-signed JWT is missing")]
    MissingIssuerJwt,

    /// A compact JWT component did not contain exactly three non-empty JWS parts.
    #[error("{component} must be a compact JWS with three non-empty parts")]
    InvalidJwtCompact {
        /// Human-readable component name for diagnostics.
        component: &'static str,
    },

    /// The JOSE header uses the unsecured `none` algorithm.
    #[error("{component} uses the unsecured 'none' algorithm")]
    UnsecuredJwt {
        /// Human-readable component name for diagnostics.
        component: &'static str,
    },

    /// JWT header or claim decoding failed.
    #[error("failed to decode {component}")]
    JwtDecoding {
        /// Human-readable component name for diagnostics.
        component: &'static str,
        /// Underlying JWT decoding error.
        #[source]
        source: jsonwebtoken::errors::Error,
    },

    /// A JWT component failed SD-JWT VC profile validation.
    #[error("invalid {component}: {reason}")]
    InvalidJwtProfile {
        /// Human-readable component name for diagnostics.
        component: &'static str,
        /// Profile validation failure.
        reason: &'static str,
    },

    /// A disclosure component was empty.
    #[error("disclosure at index {index} is empty")]
    EmptyDisclosure {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
    },

    /// A disclosure was not valid unpadded base64url.
    #[error("disclosure at index {index} is not valid base64url")]
    DisclosureBase64 {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
        /// Underlying base64 decode error.
        #[source]
        source: base64::DecodeError,
    },

    /// A disclosure decoded to invalid JSON.
    #[error("disclosure at index {index} is not valid JSON")]
    DisclosureJson {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
        /// Underlying JSON decode error.
        #[source]
        source: serde_json::Error,
    },

    /// A disclosure JSON value was not the expected two- or three-element array.
    #[error("disclosure at index {index} must be a two- or three-element array")]
    InvalidDisclosureShape {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
    },

    /// A disclosure salt or claim name had the wrong JSON type.
    #[error("disclosure at index {index} has invalid {field}")]
    InvalidDisclosureField {
        /// Zero-based disclosure index inside the SD-JWT.
        index: usize,
        /// Field name used in the diagnostic.
        field: &'static str,
    },
}
