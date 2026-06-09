use serde::{Deserialize, Serialize};

use super::{Error, Jwt, KEY_BINDING_JWT_COMPONENT};

const KEY_BINDING_JWT_TYP: &str = "kb+jwt";

/// Key Binding JWT carried by an SD-JWT presentation.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyBindingJwt<'a> {
    jwt: Jwt<'a, KeyBindingClaims>,
}

impl<'a> KeyBindingJwt<'a> {
    /// Decodes a compact Key Binding JWT.
    pub fn decode_unverified(raw: &'a str) -> Result<Self, Error> {
        let jwt = Jwt::<KeyBindingClaims>::decode_unverified(raw, KEY_BINDING_JWT_COMPONENT)?;
        validate_key_binding_profile(&jwt)?;
        Ok(Self { jwt })
    }

    /// Returns the decoded compact JWT wrapper.
    pub fn jwt(&self) -> &Jwt<'a, KeyBindingClaims> {
        &self.jwt
    }

    /// Returns the decoded Key Binding JWT claims.
    pub fn claims(&self) -> &KeyBindingClaims {
        self.jwt.claims()
    }

    /// Returns the original compact Key Binding JWT string.
    pub fn raw(&self) -> &'a str {
        self.jwt.raw()
    }
}

/// Claims required in an RFC 9901 Key Binding JWT payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyBindingClaims {
    /// Issued-at time as a NumericDate.
    pub iat: i64,
    /// Intended verifier audience. RFC 9901 requires this to be a single string.
    pub aud: String,
    /// Transaction nonce used for freshness/replay protection.
    pub nonce: String,
    /// Base64url-encoded hash over the issuer-signed JWT and selected disclosures.
    pub sd_hash: String,
}

fn validate_key_binding_profile(jwt: &Jwt<'_, KeyBindingClaims>) -> Result<(), Error> {
    match jwt.header().typ.as_deref() {
        Some(KEY_BINDING_JWT_TYP) => Ok(()),
        _ => Err(Error::InvalidJwtProfile {
            component: KEY_BINDING_JWT_COMPONENT,
            reason: "typ must be kb+jwt",
        }),
    }
}