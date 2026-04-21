pub mod pkce;

use serde::Deserialize;
use serde::Serialize;
use serde::Serializer;

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
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}
