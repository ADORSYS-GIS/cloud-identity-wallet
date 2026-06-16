use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum RedirectUriKeyError {
    #[error("expected redirect_uri client identifier prefix, got: {0}")]
    InvalidClientIdPrefix(String),

    #[error("invalid redirect URI: {message}")]
    InvalidRedirectUri {
        message: Cow<'static, str>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("failed to fetch verifier metadata")]
    MetadataFetchFailed {
        message: Option<Cow<'static, str>>,
        status: Option<u16>,
        body: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("invalid verifier metadata: {0}")]
    InvalidMetadata(String),

    #[error("failed to fetch JWKS")]
    JwksFetchFailed {
        message: Option<Cow<'static, str>>,
        status: Option<u16>,
        body: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("failed to parse JWKS: {0}")]
    JwksParseFailed(String),

    #[error("JWKS contains no keys")]
    EmptyJwks,

    #[error("no key found with kid '{0}' in verifier JWKS")]
    KeyNotFound(String),

    #[error("failed to convert JWK to DecodingKey: {0}")]
    KeyConversionFailed(String),
}
