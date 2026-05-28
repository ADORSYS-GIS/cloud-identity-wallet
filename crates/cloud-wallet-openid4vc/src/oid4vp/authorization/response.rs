use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use url::Url;

use crate::errors::{Error, ErrorKind};

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
    /// Validates the VP token contents.
    ///
    /// Returns [`ErrorKind::InvalidAuthorizationResponse`] if the token is empty,
    /// if a multiple-entry token is empty, or if it contains invalid presentation values.
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Single(value) => {
                if value.trim().is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidAuthorizationResponse,
                        "vp_token must not be empty",
                    ));
                }
            }
            Self::Multiple(entries) => {
                if entries.is_empty() {
                    return Err(Error::message(
                        ErrorKind::InvalidAuthorizationResponse,
                        "vp_token must contain at least one credential query entry",
                    ));
                }

                for (query_id, presentations) in entries {
                    if query_id.trim().is_empty() {
                        return Err(Error::message(
                            ErrorKind::InvalidAuthorizationResponse,
                            "vp_token contains an empty credential query id",
                        ));
                    }

                    if presentations.is_empty() {
                        return Err(Error::message(
                            ErrorKind::InvalidAuthorizationResponse,
                            format!(
                                "vp_token entry '{query_id}' must contain at least one presentation"
                            ),
                        ));
                    }

                    for presentation in presentations {
                        if !presentation.is_string() && !presentation.is_object() {
                            return Err(Error::message(
                                ErrorKind::InvalidAuthorizationResponse,
                                format!(
                                    "vp_token entry '{query_id}' contains an invalid presentation value"
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn as_form_value(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Single(value) => Ok(value.clone()),
            Self::Multiple(entries) => serde_json::to_string(entries),
        }
    }
}

impl Serialize for VpToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_form_value().map_err(serde::ser::Error::custom)?)
    }
}

/// Authorization Response parameters for OpenID4VP.
///
/// This type is serialized as `application/x-www-form-urlencoded` for the
/// `direct_post` response mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    /// The VP token returned to the Verifier.
    pub vp_token: VpToken,

    /// Optional state value echoed from the authorization request.
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

    /// Validates the response payload.
    pub fn validate(&self) -> Result<(), Error> {
        self.vp_token.validate()
    }
}

impl Serialize for AuthorizationResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut struct_serializer = serializer.serialize_struct(
            "AuthorizationResponse",
            if self.state.is_some() { 2 } else { 1 },
        )?;

        struct_serializer.serialize_field("vp_token", &self.vp_token)?;
        if let Some(state) = &self.state {
            struct_serializer.serialize_field("state", state)?;
        }
        struct_serializer.end()
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
    fn validates_single_vp_token() {
        let token = VpToken::Single("eyJhbGciOiJFUzI1NiJ9...".to_string());

        assert!(token.validate().is_ok());
    }

    #[test]
    fn rejects_empty_single_vp_token() {
        let token = VpToken::Single("   ".to_string());

        let err = token.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationResponse);
        assert!(err.to_string().contains("vp_token must not be empty"));
    }

    #[test]
    fn validates_multiple_vp_token() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![
                serde_json::Value::String("eyJhbGciOiJFUzI1NiJ9...".to_string()),
                json!({"format": "dc+sd-jwt"}),
            ],
        );

        let token = VpToken::Multiple(entries);

        assert!(token.validate().is_ok());
    }

    #[test]
    fn rejects_empty_multiple_vp_token() {
        let token = VpToken::Multiple(BTreeMap::new());

        let err = token.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationResponse);
        assert!(
            err.to_string()
                .contains("at least one credential query entry")
        );
    }

    #[test]
    fn rejects_invalid_presentation_value_in_multiple_vp_token() {
        let mut entries = BTreeMap::new();
        entries.insert("my_credential".to_string(), vec![serde_json::Value::Null]);

        let token = VpToken::Multiple(entries);

        let err = token.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidAuthorizationResponse);
        assert!(err.to_string().contains("invalid presentation value"));
    }

    #[test]
    fn serializes_single_vp_token_as_form_body() {
        let response = AuthorizationResponse::new(VpToken::Single("vp-token-value".to_string()))
            .with_state("state-123");

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(params.get("vp_token"), Some(&"vp-token-value".to_string()));
        assert_eq!(params.get("state"), Some(&"state-123".to_string()));
    }

    #[test]
    fn serializes_multiple_vp_token_as_json_string_in_form_body() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "my_credential".to_string(),
            vec![serde_json::Value::String(
                "eyJhbGciOiJFUzI1NiJ9...".to_string(),
            )],
        );

        let response = AuthorizationResponse::new(VpToken::Multiple(entries));

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(encoded.as_bytes())
            .into_owned()
            .collect();

        assert_eq!(
            params.get("vp_token"),
            Some(&r#"{"my_credential":["eyJhbGciOiJFUzI1NiJ9..."]}"#.to_string())
        );
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

    #[test]
    fn validates_authorization_response() {
        let response = AuthorizationResponse::new(VpToken::Single("vp-token-value".to_string()));

        assert!(response.validate().is_ok());
    }

    #[test]
    fn rejects_blank_state_when_serialized_as_form_body_is_not_needed() {
        let response = AuthorizationResponse::new(VpToken::Single("vp-token-value".to_string()))
            .with_state("");

        let encoded = serde_urlencoded::to_string(&response).expect("serialize");
        assert!(encoded.contains("state="));
    }
}
