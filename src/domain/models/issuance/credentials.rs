use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::fmt;
use uuid::Uuid;

/// Deserialize a query parameter that may be either a comma-separated string
/// (`?credential_types=A,B`) or a JSON sequence (used in unit tests).
pub fn deserialize_string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrSeq;

    impl<'de> Visitor<'de> for StringOrSeq {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a comma-separated string or sequence of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect())
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrSeq)
}

/// Query parameters accepted by `GET /api/v1/credentials`.
#[derive(Debug, Deserialize)]
pub struct CredentialListQuery {
    /// Filter by credential configuration IDs. Pass a single value or a
    /// comma-separated list: `?credential_types=A` or `?credential_types=A,B`.
    #[serde(default, deserialize_with = "deserialize_string_or_seq")]
    pub credential_types: Vec<String>,
    /// Filter by lifecycle status (`active`, `revoked`, `expired`, `suspended`).
    pub status: Option<String>,
    /// Filter by wire format (`dc+sd-jwt`, `mso_mdoc`, etc.).
    pub format: Option<String>,
    /// Filter by issuer URI.
    pub issuer: Option<String>,
}

/// Response body for a single verifiable credential stored in the wallet.
///
/// `claims` is always `null` in the current implementation; format-specific
/// claim decoding will be added in a future iteration.
#[derive(Debug, Serialize)]
pub struct CredentialRecord {
    pub id: Uuid,
    pub credential_configuration_id: String,
    pub format: String,
    pub issuer: String,
    pub status: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Decoded credential claims. Format-specific parsing is out of scope for
    /// this implementation; field is always `null`.
    pub claims: serde_json::Value,
}

/// Response body for `GET /api/v1/credentials`.
#[derive(Debug, Serialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialRecord>,
}
