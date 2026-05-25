mod disclosure;
mod error;
mod jwt;
mod kb_jwt;
mod metadata;
#[cfg(test)]
mod tests;

pub use disclosure::Disclosure;
pub use error::Error;
pub use jwt::Jwt;
pub use kb_jwt::{KeyBindingClaims, KeyBindingJwt};
pub use metadata::IssuerMetadataError;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use crate::core::rfc7519::RFC7519Claims;
use crate::formats::sd_jwt::jwt::validate_compact_jws;

type Object = serde_json::Map<String, Value>;

const ISSUER_JWT_COMPONENT: &str = "Issuer-Signed JWT";
const KEY_BINDING_JWT_COMPONENT: &str = "Key Binding JWT";
const SD_JWT_VC_TYP: &str = "dc+sd-jwt";
const TRANSITIONAL_SD_JWT_VC_TYP: &str = "vc+sd-jwt";

/// Parsed SD-JWT VC in combined serialization form.
#[derive(Debug, Clone, PartialEq)]
pub struct SdJwt<'a> {
    /// Issuer signed JWT.
    jwt: Jwt<'a, SdJwtClaims>,
    /// Disclosures.
    disclosures: Vec<Disclosure<'a>>,
    /// The optional key binding JWT.
    key_binding: Option<KeyBindingJwt<'a>>,
}

impl<'a> SdJwt<'a> {
    /// Parses an SD-JWT VC from [RFC 9901] combined serialization.
    ///
    /// The accepted issued form is `<issuer-jwt>~<disclosure>*~`. The accepted
    /// presentation form with key binding is
    /// `<issuer-jwt>~<disclosure>*~<kb-jwt>`.
    ///
    /// [RFC 9901]: https://datatracker.ietf.org/doc/html/rfc9901
    pub fn parse(raw: &'a str) -> Result<Self, Error> {
        if !raw.contains('~') {
            return Err(Error::MissingSdJwtSeparator);
        }

        let parts = raw.split('~').collect::<Vec<_>>();
        let issuer_jwt = parts
            .first()
            .copied()
            .filter(|part| !part.is_empty())
            .ok_or(Error::MissingIssuerJwt)?;

        let jwt = Jwt::<SdJwtClaims>::decode_unverified(issuer_jwt, ISSUER_JWT_COMPONENT)?;
        validate_sd_jwt_vc_profile(&jwt)?;

        let (disclosure_parts, key_binding) = match parts.last().copied() {
            Some("") => (&parts[1..parts.len() - 1], None),
            Some(kb_jwt) => {
                validate_compact_jws(kb_jwt, KEY_BINDING_JWT_COMPONENT)
                    .map_err(|_| Error::MissingSdJwtTrailingSeparator)?;
                let key_binding = KeyBindingJwt::decode_unverified(kb_jwt)?;
                (&parts[1..parts.len() - 1], Some(key_binding))
            }
            None => unreachable!("split always returns at least one segment"),
        };

        let disclosures = disclosure_parts
            .iter()
            .enumerate()
            .map(|(index, raw)| Disclosure::parse(raw, index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            jwt,
            disclosures,
            key_binding,
        })
    }

    /// Returns the decoded issuer-signed JWT.
    pub fn jwt(&self) -> &Jwt<'a, SdJwtClaims> {
        &self.jwt
    }

    /// Consumes the SD-JWT and returns the decoded issuer-signed JWT.
    pub fn into_jwt(self) -> Jwt<'a, SdJwtClaims> {
        self.jwt
    }

    /// Returns the parsed disclosure list in combined-serialization order.
    pub fn disclosures(&self) -> &[Disclosure<'a>] {
        &self.disclosures
    }

    /// Consumes the SD-JWT and returns the parsed disclosure list.
    pub fn into_disclosures(self) -> Vec<Disclosure<'a>> {
        self.disclosures
    }

    /// Returns the optional key binding JWT.
    pub fn key_binding(&self) -> Option<&KeyBindingJwt<'a>> {
        self.key_binding.as_ref()
    }

    /// Returns true when the combined serialization includes a key binding JWT.
    pub fn has_key_binding(&self) -> bool {
        self.key_binding.is_some()
    }
}

/// Claims carried by an SD-JWT VC issuer-signed JWT.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtClaims {
    /// Standard JWT registered claims.
    #[serde(flatten)]
    pub rfc7519: RFC7519Claims,

    /// Verifiable Credential Type URI.
    pub vct: String,

    /// Hash of the Type Metadata document to provide integrity.
    #[serde(rename = "vct#integrity")]
    pub vct_integrity: Option<String>,

    /// Selective disclosure hash algorithm. Defaults to `sha-256` at the
    /// disclosure-processing layer when omitted.
    #[serde(rename = "_sd_alg")]
    pub sd_alg: Option<String>,

    /// Disclosure digests present at the root of the issuer-signed JWT.
    #[serde(default, rename = "_sd")]
    pub sd: Vec<String>,

    /// Holder key confirmation material.
    pub cnf: Option<CnfClaim>,

    /// Optional credential status information.
    pub status: Option<StatusClaim>,

    /// Non-registered, non-SD-JWT-VC-specific claims.
    #[serde(flatten)]
    pub properties: Object,
}

/// Confirmation claim (`cnf`) used for holder binding.
/// See [RFC7800](https://www.rfc-editor.org/rfc/rfc7800.html#section-3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CnfClaim {
    /// Holder public key, when represented directly as a JWK.
    Jwk(Value),
    /// Encoded JWK in its compact serialization form.
    Jwe(String),
    /// Key ID.
    Kid(String),
    /// JWK from a JWK set identified by `kid`.
    #[serde(untagged)]
    Jku {
        /// URL of the JWK Set.
        jku: Url,
        /// kid of the referenced JWK.
        kid: String,
    },
    /// Additional confirmation methods not yet modelled.
    ///
    /// This is intentionally permissive for forward compatibility with new
    /// confirmation methods. Callers that require holder binding must match one
    /// of the concrete variants they support.
    #[serde(untagged)]
    Custom(Value),
}

/// Status information for a referenced token as defined in the [token status-list draft].
///
/// [token status-list draft]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-20
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusClaim {
    /// Token Status List reference, when the `status_list` mechanism is used.
    pub status_list: Option<StatusListInfo>,
}

/// Reference to a Token Status List entry for this credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusListInfo {
    /// Non-negative index of the credential status bit(s) in the referenced list.
    pub idx: u64,

    /// URI of the Status List Token.
    pub uri: Url,
}

fn validate_sd_jwt_vc_profile(jwt: &Jwt<'_, SdJwtClaims>) -> Result<(), Error> {
    match jwt.header().typ.as_deref() {
        Some(SD_JWT_VC_TYP | TRANSITIONAL_SD_JWT_VC_TYP) => {}
        _ => {
            return Err(Error::InvalidJwtProfile {
                component: ISSUER_JWT_COMPONENT,
                reason: "typ must be dc+sd-jwt",
            });
        }
    }

    if jwt.claims().vct.trim().is_empty() {
        return Err(Error::InvalidJwtProfile {
            component: ISSUER_JWT_COMPONENT,
            reason: "vct must not be empty",
        });
    }
    Ok(())
}
