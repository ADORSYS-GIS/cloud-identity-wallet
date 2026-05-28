use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use url::Url;

/// A VP token returned in an OpenID4VP authorization response.
///
/// The `Single` variant represents a single presentation value.
/// The `Multiple` variant represents a JSON object keyed by `CredentialQuery.id`
/// values, where each key maps to one or more presentation values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpToken {
    Single(String),
    Multiple(BTreeMap<String, Vec<serde_json::Value>>),
}

impl VpToken {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Single(value) => {
                if value.trim().is_empty() {
                    return Err("vp_token must not be empty".to_string());
                }
            }
            Self::Multiple(entries) => {
                if entries.is_empty() {
                    return Err(
                        "vp_token must contain at least one credential query entry".to_string()
                    );
                }

                for (query_id, presentations) in entries {
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
            }
        }

        Ok(())
    }

    fn into_form_value(self) -> Result<String, serde_json::Error> {
        match self {
            Self::Single(value) => Ok(value),
            Self::Multiple(entries) => serde_json::to_string(&entries),
        }
    }
}

impl Serialize for VpToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        match self {
            Self::Single(value) => serializer.serialize_str(value),
            Self::Multiple(entries) => serializer
                .serialize_str(&serde_json::to_string(entries).map_err(serde::ser::Error::custom)?),
        }
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
            Multiple(BTreeMap<String, Vec<serde_json::Value>>),
        }

        let token = match RawVpToken::deserialize(deserializer)? {
            RawVpToken::String(value) => {
                if value.trim_start().starts_with('{') {
                    let entries = serde_json::from_str::<BTreeMap<String, Vec<serde_json::Value>>>(
                        value.trim(),
                    )
                    .map_err(de::Error::custom)?;
                    VpToken::Multiple(entries)
                } else {
                    VpToken::Single(value)
                }
            }
            RawVpToken::Multiple(entries) => VpToken::Multiple(entries),
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
    fn serializes_single_vp_token_to_json_string() {
        let token = VpToken::Single("eyJhbGciOiJFUzI1NiJ9...".to_string());

        assert_eq!(
            token.clone().into_form_value().expect("form value"),
            "eyJhbGciOiJFUzI1NiJ9..."
        );

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(json, json!("eyJhbGciOiJFUzI1NiJ9..."));
    }

    #[test]
    fn rejects_empty_single_vp_token_on_serialize() {
        let token = VpToken::Single("   ".to_string());

        let err = serde_json::to_string(&token).unwrap_err();
        assert!(err.to_string().contains("vp_token must not be empty"));
    }

    #[test]
    fn serializes_multiple_vp_token_to_json_string() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![
                serde_json::Value::String("eyJhbGciOiJFUzI1NiJ9...".to_string()),
                json!({"format": "dc+sd-jwt"}),
            ],
        );

        let token = VpToken::Multiple(entries);

        assert!(token.clone().into_form_value().is_ok());

        let json = serde_json::to_value(&token).expect("serialize");

        assert_eq!(
            json,
            json!(r#"{"my_credential":["eyJhbGciOiJFUzI1NiJ9...",{"format":"dc+sd-jwt"}]}"#)
        );
    }

    #[test]
    fn rejects_empty_multiple_vp_token_on_serialize() {
        let token = VpToken::Multiple(BTreeMap::new());

        let err = serde_json::to_string(&token).unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one credential query entry")
        );
    }

    #[test]
    fn rejects_invalid_presentation_value_in_multiple_vp_token_on_serialize() {
        let mut entries = BTreeMap::new();
        entries.insert("my_credential".to_string(), vec![serde_json::Value::Null]);

        let token = VpToken::Multiple(entries);

        let err = serde_json::to_string(&token).unwrap_err();
        assert!(err.to_string().contains("invalid presentation value"));
    }

    #[test]
    fn round_trips_single_vp_token_via_form_body() {
        let response = AuthorizationResponse::new(VpToken::Single("vp-token-value".to_string()))
            .with_state("state-123");

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        let decoded: AuthorizationResponse =
            serde_urlencoded::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded, response);

        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(params.get("vp_token"), Some(&"vp-token-value".to_string()));
        assert_eq!(params.get("state"), Some(&"state-123".to_string()));
    }

    #[test]
    fn round_trips_multiple_vp_token_via_form_body() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![serde_json::Value::String(
                "eyJhbGciOiJFUzI1NiJ9...".to_string(),
            )],
        );

        let response = AuthorizationResponse::new(VpToken::Multiple(entries));

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        let decoded: AuthorizationResponse =
            serde_urlencoded::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded, response);

        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("vp_token"),
            Some(&r#"{"my_credential":["eyJhbGciOiJFUzI1NiJ9..."]}"#.to_string())
        );
    }

    #[test]
    fn deserializes_multiple_vp_token_from_json_object_string() {
        let encoded =
            "vp_token=%7B%22my_credential%22%3A%5B%22eyJhbGciOiJFUzI1NiJ9...%22%5D%7D&state=xyz";
        let response: AuthorizationResponse =
            serde_urlencoded::from_str(encoded).expect("deserialize");

        match response.vp_token {
            VpToken::Multiple(entries) => {
                assert_eq!(entries.get("my_credential").unwrap().len(), 1);
            }
            VpToken::Single(_) => panic!("expected multiple vp_token"),
        }
        assert_eq!(response.state.as_deref(), Some("xyz"));
    }

    #[test]
    fn rejects_invalid_vp_token_on_deserialize() {
        let err =
            serde_urlencoded::from_str::<AuthorizationResponse>("vp_token=%20%20").unwrap_err();
        assert!(err.to_string().contains("vp_token must not be empty"));
    }

    #[test]
    fn rejects_invalid_multiple_vp_token_on_deserialize() {
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
