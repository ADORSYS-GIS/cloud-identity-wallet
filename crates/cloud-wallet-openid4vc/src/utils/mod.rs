mod css_color;
pub mod pkce;

pub use css_color::*;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::errors::{Error, ErrorKind};

/// Implements serde string conversion and display for string-valued enums with
/// an `Other(String)` extension variant.
#[macro_export]
macro_rules! impl_string_enum {
    ($ty:ident, { $($variant:ident => $wire:literal),+ $(,)? }, $field:literal) => {
        impl $ty {
            fn parse(value: String) -> Result<Self, String> {
                if value.trim().is_empty() {
                    return Err(format!("{} must not be empty", $field));
                }

                Ok(match value.as_str() {
                    $($wire => Self::$variant,)+
                    _ => Self::Other(value),
                })
            }

            fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Other(value) => value,
                }
            }
        }

        impl serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// Serialize a value as a JSON string
pub fn serialize_json_string<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    let j = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&j)
}

/// Deserialize a JSON string into a value
pub fn deserialize_json_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: for<'a> Deserialize<'a>,
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(de::Error::custom)
}

pub fn deserialize_non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    if value.is_empty() {
        return Err(de::Error::custom("value must not be empty"));
    }

    Ok(value)
}

pub fn deserialize_non_empty_string_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;

    if values.is_empty() {
        return Err(de::Error::custom(
            "proof arrays must contain at least one entry",
        ));
    }

    if values.iter().any(String::is_empty) {
        return Err(de::Error::custom(
            "proof arrays must not contain empty entries",
        ));
    }

    Ok(values)
}

pub fn deserialize_non_empty_object_vec<'de, D>(
    deserializer: D,
) -> Result<Vec<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;

    if values.is_empty() {
        return Err(serde::de::Error::custom(
            "proof arrays must contain at least one entry",
        ));
    }

    if values.iter().any(|value| !value.is_object()) {
        return Err(de::Error::custom("di_vp proofs must contain JSON objects"));
    }

    Ok(values)
}

pub fn deserialize_single_attestation<'de, D>(deserializer: D) -> Result<[String; 1], D::Error>
where
    D: Deserializer<'de>,
{
    let attestation = <[String; 1]>::deserialize(deserializer)?;

    if attestation[0].is_empty() {
        return Err(de::Error::custom("attestation proof must not be empty"));
    }

    Ok(attestation)
}

pub fn validate_non_empty_string_array(values: &[String], field: &str) -> Result<(), Error> {
    validate_non_empty_array(values, field)?;

    if values.iter().any(|value| value.trim().is_empty()) {
        return invalid_client_metadata(format!("{field} must not contain empty strings"));
    }
    Ok(())
}

pub fn validate_non_empty_array<T>(values: &[T], field: &str) -> Result<(), Error> {
    if values.is_empty() {
        return invalid_client_metadata(format!("{field} must be a non-empty array"));
    }
    Ok(())
}

fn invalid_client_metadata<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::message(
        ErrorKind::InvalidClientMetadata,
        message.into(),
    ))
}

/// A parsed, duplicate-free set of query parameters.
#[derive(Debug)]
pub struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    /// Parses a raw query string, **rejecting** duplicate occurrences of any
    /// key listed in `recognized`.
    ///
    /// Percent-encoding and `+`-as-space are decoded for every key and value.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidAuthorizationResponse`] if a key that
    /// appears in `recognized` is present more than once.
    pub fn parse(query: &str, recognized: &[&str]) -> Result<Self, Error> {
        let pairs: Vec<(String, String)> = query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim();
                let value = parts.next().unwrap_or("");

                if key.is_empty() {
                    return None;
                }

                Some((decode_form_value(key), decode_form_value(value)))
            })
            .collect();

        // Reject duplicate recognized parameters.
        for key in recognized {
            let count = pairs.iter().filter(|(k, _)| k == key).count();
            if count > 1 {
                return Err(Error::message(
                    ErrorKind::InvalidAuthorizationResponse,
                    format!("duplicate '{key}' parameter in authorization response"),
                ));
            }
        }

        Ok(Self { pairs })
    }

    /// Returns the value for `key`, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Decodes a single `application/x-www-form-urlencoded` value.
///
/// Replaces `+` with a space, then applies percent-decoding.
fn decode_form_value(s: &str) -> String {
    let plus_decoded = s.replace('+', " ");
    percent_decode_str(&plus_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOGNIZED: &[&str] = &["code", "state"];

    #[test]
    fn parses_simple_pair() {
        let params = QueryParams::parse("code=abc123", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc123"));
        assert_eq!(params.get("state"), None);
    }

    #[test]
    fn parses_multiple_pairs() {
        let params = QueryParams::parse("code=abc&state=xyz", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
        assert_eq!(params.get("state"), Some("xyz"));
    }

    #[test]
    fn decodes_percent_encoding() {
        let params = QueryParams::parse("state=state%3Dvalue%26other%3Ddata", RECOGNIZED).unwrap();
        assert_eq!(params.get("state"), Some("state=value&other=data"));
    }

    #[test]
    fn decodes_plus_as_space() {
        let params = QueryParams::parse("state=hello+world", RECOGNIZED).unwrap();
        assert_eq!(params.get("state"), Some("hello world"));
    }

    #[test]
    fn rejects_duplicate_recognized_key() {
        let err = QueryParams::parse("code=a&code=b", RECOGNIZED).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationResponse);
        assert!(err.to_string().contains("duplicate 'code'"));
    }

    #[test]
    fn allows_duplicate_unrecognized_key() {
        // Unrecognized keys are not subject to duplicate detection.
        let params = QueryParams::parse("code=abc&extra=1&extra=2", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
    }

    #[test]
    fn ignores_empty_key_segments() {
        let params = QueryParams::parse("&code=abc&&", RECOGNIZED).unwrap();
        assert_eq!(params.get("code"), Some("abc"));
    }
}
