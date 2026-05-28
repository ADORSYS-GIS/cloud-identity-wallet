use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use url::Url;

/// A VP token returned in an OpenID4VP authorization response.
///
/// Per the spec, the value is a JSON object keyed by `CredentialQuery.id`,
/// where each entry contains one or more presentations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpToken {
    entries: BTreeMap<String, Vec<serde_json::Value>>,
}

impl VpToken {
    /// Creates a new VP token from DCQL query entries.
    pub fn new(entries: BTreeMap<String, Vec<serde_json::Value>>) -> Self {
        Self { entries }
    }

    /// Returns the underlying DCQL entries.
    pub fn entries(&self) -> &BTreeMap<String, Vec<serde_json::Value>> {
        &self.entries
    }

    fn validate(&self) -> Result<(), String> {
        if self.entries.is_empty() {
            return Err("vp_token must contain at least one credential query entry".to_string());
        }

        for (query_id, presentations) in &self.entries {
            if query_id.trim().is_empty() {
                return Err("vp_token contains an empty credential query id".to_string());
            }

            if presentations.is_empty() {
                return Err(format!(
                    "vp_token entry '{query_id}' must contain at least one presentation"
                ));
            }

            for presentation in presentations {
                if !presentation.is_string() && !presentation.is_object() {
                    return Err(format!(
                        "vp_token entry '{query_id}' contains an invalid presentation value"
                    ));
                }
            }
        }

        Ok(())
    }
}

impl Serialize for VpToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(
            &serde_json::to_string(&self.entries).map_err(serde::ser::Error::custom)?,
        )
    }
}

impl<'de> Deserialize<'de> for VpToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawVpToken {
            String(String),
            Object(BTreeMap<String, Vec<serde_json::Value>>),
        }

        let token = match RawVpToken::deserialize(deserializer)? {
            RawVpToken::String(value) => {
                if value.trim_start().starts_with('{') {
                    let entries = serde_json::from_str::<BTreeMap<String, Vec<serde_json::Value>>>(
                        value.trim(),
                    )
                    .map_err(de::Error::custom)?;
                    VpToken::new(entries)
                } else {
                    return Err(de::Error::custom(
                        "vp_token must be a JSON-encoded object of credential query entries",
                    ));
                }
            }
            RawVpToken::Object(entries) => VpToken::new(entries),
        };

        token.validate().map_err(de::Error::custom)?;
        Ok(token)
    }
}

/// Authorization Response parameters for OpenID4VP.
///
/// This type is serialized as `application/x-www-form-urlencoded` for the
/// `direct_post` response mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponse {
    /// The VP token returned to the Verifier.
    pub vp_token: VpToken,

    /// Optional state value echoed from the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl AuthorizationResponse {
    /// Creates a new authorization response.
    pub fn new(vp_token: VpToken) -> Self {
        Self {
            vp_token,
            state: None,
        }
    }

    /// Adds a state value to the response.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }
}

/// Response to the verifier when the Wallet uses the `direct_post` response mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectPostResponse {
    /// Optional redirect URI provided by the Verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<Url>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_vp_token_with_single_entry_to_json_string() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![serde_json::Value::String(
                "eyJhbGciOiJFUzI1NiJ9...".to_string(),
            )],
        );
        let token = VpToken::new(entries);

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(
            json,
            json!(r#"{"my_credential":["eyJhbGciOiJFUzI1NiJ9..."]}"#)
        );
    }

    #[test]
    fn serializes_vp_token_to_json_string() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![
                serde_json::Value::String("eyJhbGciOiJFUzI1NiJ9...".to_string()),
                json!({"format": "dc+sd-jwt"}),
            ],
        );

        let token = VpToken::new(entries);

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(
            json,
            json!(r#"{"my_credential":["eyJhbGciOiJFUzI1NiJ9...",{"format":"dc+sd-jwt"}]}"#)
        );
    }

    #[test]
    fn rejects_empty_vp_token_on_serialize() {
        let token = VpToken::new(BTreeMap::new());

        let err = serde_json::to_string(&token).unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one credential query entry")
        );
    }

    #[test]
    fn rejects_invalid_presentation_value_on_serialize() {
        let mut entries = BTreeMap::new();
        entries.insert("my_credential".to_string(), vec![serde_json::Value::Null]);

        let token = VpToken::new(entries);

        let err = serde_json::to_string(&token).unwrap_err();
        assert!(err.to_string().contains("invalid presentation value"));
    }

    #[test]
    fn round_trips_vp_token_via_form_body() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![serde_json::Value::String("vp-token-value".to_string())],
        );

        let response = AuthorizationResponse::new(VpToken::new(entries)).with_state("state-123");

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        let decoded: AuthorizationResponse =
            serde_urlencoded::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded, response);

        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("vp_token"),
            Some(&r#"{"my_credential":["vp-token-value"]}"#.to_string())
        );
        assert_eq!(params.get("state"), Some(&"state-123".to_string()));
    }

    #[test]
    fn deserializes_vp_token_from_json_object_string() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![serde_json::Value::String(
                "eyJhbGciOiJFUzI1NiJ9...".to_string(),
            )],
        );

        let token = serde_json::to_string(&VpToken::new(entries)).expect("serialize");
        let parsed: VpToken = serde_json::from_str(&token).expect("deserialize");

        assert_eq!(parsed.entries().get("my_credential").unwrap().len(), 1);
    }

    #[test]
    fn rejects_invalid_vp_token_on_deserialize() {
        let err =
            serde_urlencoded::from_str::<AuthorizationResponse>("vp_token=%20%20").unwrap_err();
        assert!(
            err.to_string()
                .contains("vp_token must be a JSON-encoded object")
        );
    }

    #[test]
    fn rejects_empty_presentation_list_on_deserialize() {
        let encoded = "vp_token=%7B%22my_credential%22%3A%5B%5D%7D";
        let err = serde_urlencoded::from_str::<AuthorizationResponse>(encoded).unwrap_err();
        assert!(err.to_string().contains("at least one presentation"));
    }

    #[test]
    fn serializes_direct_post_response() {
        let response = DirectPostResponse {
            redirect_uri: Some(
                Url::parse("https://client.example.org/cb#response_code=abc").unwrap(),
            ),
        };

        let json = serde_json::to_value(&response).expect("serialize");

        assert_eq!(
            json,
            json!({
                "redirect_uri": "https://client.example.org/cb#response_code=abc"
            })
        );
    }
}
