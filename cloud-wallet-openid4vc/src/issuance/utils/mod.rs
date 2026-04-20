pub mod pkce;

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
