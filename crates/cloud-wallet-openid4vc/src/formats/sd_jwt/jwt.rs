use serde::de::DeserializeOwned;

use jsonwebtoken::{Header, dangerous::insecure_decode};

use super::Error;

/// A compact JWT.
///
/// This type is intentionally only a structural representation.
/// Callers must not treat the claims as trusted until the signature and trust policy
/// have been validated.
#[derive(Debug, Clone, PartialEq)]
pub struct Jwt<'a, T> {
    /// JWT header.
    header: Header,
    /// JWT claims.
    claims: T,
    /// Raw JWT string.
    raw: &'a str,
}

impl<'a, T> Jwt<'a, T>
where
    T: DeserializeOwned,
{
    /// Decodes a compact JWT without verifying its signature.
    pub fn decode_unverified(raw: &'a str, component: &'static str) -> Result<Self, Error> {
        validate_compact_jws(raw, component)?;
        reject_none_alg(raw, component)?;

        let token_data =
            insecure_decode::<T>(raw).map_err(|source| Error::JwtDecoding { component, source })?;

        Ok(Self {
            header: token_data.header,
            claims: token_data.claims,
            raw,
        })
    }
}

impl<'a, T> Jwt<'a, T> {
    /// Returns the decoded JOSE header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the decoded JWT claims.
    pub fn claims(&self) -> &T {
        &self.claims
    }

    /// Consumes the JWT and returns the decoded claims.
    pub fn into_claims(self) -> T {
        self.claims
    }

    /// Returns the original compact JWT string.
    pub fn raw(&self) -> &'a str {
        self.raw
    }
}

pub(crate) fn validate_compact_jws(raw: &str, component: &'static str) -> Result<(), Error> {
    let mut segments = raw.split('.');
    let header = segments.next();
    let claims = segments.next();
    let signature = segments.next();

    match (header, claims, signature, segments.next()) {
        (Some(header), Some(claims), Some(signature), None)
            if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
        {
            Ok(())
        }
        _ => Err(Error::InvalidJwtCompact { component }),
    }
}

fn reject_none_alg(raw: &str, component: &'static str) -> Result<(), Error> {
    let header_segment = raw
        .split('.')
        .next()
        .ok_or(Error::InvalidJwtCompact { component })?;
    let header_value = decode_json_segment(header_segment)
        .map_err(|source| Error::JwtDecoding { component, source })?;

    if header_value
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|alg| alg.eq_ignore_ascii_case("none"))
    {
        return Err(Error::UnsecuredJwt { component });
    }
    Ok(())
}

fn decode_json_segment(segment: &str) -> jsonwebtoken::errors::Result<serde_json::Value> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::errors::{Error, ErrorKind};

    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|err| Error::from(ErrorKind::Base64(err)))?;
    serde_json::from_slice(&decoded).map_err(Into::into)
}
