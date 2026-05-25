use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Set of IANA registered claims in [RFC 7519].
///
/// [RFC 7519]: https://tools.ietf.org/html/rfc7519#section-4.1
#[skip_serializing_none]
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RFC7519Claims {
    /// Issuer claim.
    pub iss: Option<String>,
    /// Subject claim.
    pub sub: Option<String>,
    /// Audience claim.
    pub aud: Option<String>,
    /// Expiration time as a NumericDate.
    pub exp: Option<i64>,
    /// Not-before time as a NumericDate.
    pub nbf: Option<i64>,
    /// Issued-at time as a NumericDate.
    pub iat: Option<i64>,
    /// JWT identifier claim.
    pub jti: Option<String>,
}
