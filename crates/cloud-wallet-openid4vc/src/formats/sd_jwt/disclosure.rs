use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use super::Error;

/// A single SD-JWT disclosure decoded from the combined SD-JWT serialization.
///
/// [RFC 9901] encodes disclosures as base64url JSON arrays. A three-element array
/// discloses an object property (`[salt, claim_name, claim_value]`), while a
/// two-element array discloses an array element (`[salt, claim_value]`).
///
/// [RFC 9901]: https://datatracker.ietf.org/doc/html/rfc9901
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure<'a> {
    /// The salt value.
    pub salt: String,
    /// The claim name, optional for array elements.
    pub claim_name: Option<String>,
    /// The claim Value which can be of any type.
    pub claim_value: Value,
    /// Raw Base64Url-encoded disclosure.
    raw: &'a str,
}

impl<'a> Disclosure<'a> {
    /// Parses an unpadded base64url-encoded disclosure.
    pub fn parse(raw: &'a str, index: usize) -> Result<Self, Error> {
        if raw.is_empty() {
            return Err(Error::EmptyDisclosure { index });
        }

        let decoded = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|source| Error::DisclosureBase64 { index, source })?;
        let value = serde_json::from_slice::<Value>(&decoded)
            .map_err(|source| Error::DisclosureJson { index, source })?;

        let array = match value {
            Value::Array(array) => array,
            _ => return Err(Error::InvalidDisclosureShape { index }),
        };

        match array.as_slice() {
            [salt, claim_value] => Ok(Self {
                salt: string_field(salt.clone(), index, "salt")?,
                claim_name: None,
                claim_value: claim_value.clone(),
                raw,
            }),
            [salt, claim_name, claim_value] => Ok(Self {
                salt: string_field(salt.clone(), index, "salt")?,
                claim_name: Some(string_field(claim_name.clone(), index, "claim_name")?),
                claim_value: claim_value.clone(),
                raw,
            }),
            _ => Err(Error::InvalidDisclosureShape { index }),
        }
    }

    /// Returns the original base64url-encoded disclosure string.
    pub fn raw(&self) -> &'a str {
        self.raw
    }

    /// Returns true when this disclosure describes an array element.
    pub fn is_array_element(&self) -> bool {
        self.claim_name.is_none()
    }

    /// Returns true when this disclosure describes an object property.
    pub fn is_object_element(&self) -> bool {
        self.claim_name.is_some()
    }
}

fn string_field(value: Value, index: usize, field: &'static str) -> Result<String, Error> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(Error::InvalidDisclosureField { index, field }),
    }
}
