use serde::{Deserialize, Serialize};

use super::{Error, Jwt, KEY_BINDING_JWT_COMPONENT};

pub const KEY_BINDING_JWT_TYP: &str = "kb+jwt";

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
///
/// The optional `transaction_data_hashes` and `transaction_data_hashes_alg`
/// fields are defined in [OpenID4VP §8.4] for transaction data support.
///
/// [OpenID4VP §8.4]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4
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
    /// Base64url-encoded hashes of transaction data entries that apply to this
    /// credential, per OpenID4VP §8.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes: Option<Vec<String>>,
    /// Hash algorithm used for `transaction_data_hashes`. Defaults to `sha-256`
    /// when absent, per OpenID4VP §8.4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<String>,
}

impl KeyBindingClaims {
    /// Creates a new set of Key Binding JWT claims using the current timestamp.
    pub fn new(
        aud: impl Into<String>,
        nonce: impl Into<String>,
        sd_hash: impl Into<String>,
    ) -> Self {
        Self::new_with_iat(
            time::UtcDateTime::now().unix_timestamp(),
            aud,
            nonce,
            sd_hash,
        )
    }

    /// Creates a new set of Key Binding JWT claims with an explicit issued-at timestamp.
    pub fn new_with_iat(
        iat: i64,
        aud: impl Into<String>,
        nonce: impl Into<String>,
        sd_hash: impl Into<String>,
    ) -> Self {
        Self {
            iat,
            aud: aud.into(),
            nonce: nonce.into(),
            sd_hash: sd_hash.into(),
            transaction_data_hashes: None,
            transaction_data_hashes_alg: None,
        }
    }

    /// Sets optional transaction data hashes.
    pub fn with_transaction_data(
        mut self,
        hashes: impl IntoIterator<Item = impl Into<String>>,
        alg: Option<impl Into<String>>,
    ) -> Self {
        self.transaction_data_hashes = Some(hashes.into_iter().map(Into::into).collect());
        self.transaction_data_hashes_alg = alg.map(Into::into);
        self
    }
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
