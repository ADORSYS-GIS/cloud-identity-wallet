//! OpenID4VP response and VP token models.
//!
//! See OpenID4VP Section 8.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind};

fn validate_identifier(value: &str, field: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::message(
            ErrorKind::InvalidPresentationResponse,
            format!("{field} must not be empty"),
        ));
    }

    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(Error::message(
            ErrorKind::InvalidPresentationResponse,
            format!("{field} must contain only ASCII alphanumeric characters, '_' or '-'"),
        ));
    }

    Ok(())
}

/// Individual presentation entry within a VP Token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PresentedCredential {
    /// String-encoded presentation, such as a JWT or base64url-encoded mdoc response.
    String(String),

    /// Object-encoded presentation.
    Object(Map<String, Value>),
}

impl PresentedCredential {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::String(value) if value.trim().is_empty() => Err(Error::message(
                ErrorKind::InvalidPresentationResponse,
                "vp_token entries must not contain empty strings",
            )),
            Self::Object(value) if value.is_empty() => Err(Error::message(
                ErrorKind::InvalidPresentationResponse,
                "vp_token object entries must not be empty objects",
            )),
            _ => Ok(()),
        }
    }
}

/// The OpenID4VP `vp_token` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VpToken(pub BTreeMap<String, Vec<PresentedCredential>>);

impl VpToken {
    /// Validates the VP Token shape.
    pub fn validate(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationResponse,
                "vp_token must contain at least one credential entry",
            ));
        }

        for (credential_id, presentations) in &self.0 {
            validate_identifier(credential_id, "vp_token key")?;

            if presentations.is_empty() {
                return Err(Error::message(
                    ErrorKind::InvalidPresentationResponse,
                    format!(
                        "vp_token entry '{credential_id}' must contain at least one presentation"
                    ),
                ));
            }

            for presentation in presentations {
                presentation.validate()?;
            }
        }

        Ok(())
    }
}

/// Successful OpenID4VP response parameters.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresentationResponse {
    /// Presented credentials grouped by requested credential query id.
    pub vp_token: VpToken,

    /// Optional SIOP ID Token if `vp_token id_token` was requested.
    pub id_token: Option<String>,

    /// Optional OAuth issuer identifier.
    pub iss: Option<String>,

    /// Optional state parameter echoed back to the verifier.
    pub state: Option<String>,
}

impl PresentationResponse {
    /// Validates the response.
    pub fn validate(&self) -> Result<(), Error> {
        self.vp_token.validate()
    }
}

/// Encrypted direct-post or DC API JWT response wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPresentationResponse {
    /// JWE-encoded authorization response.
    pub response: String,
}

impl EncryptedPresentationResponse {
    /// Validates the encrypted response wrapper.
    pub fn validate(&self) -> Result<(), Error> {
        if self.response.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidPresentationResponse,
                "response must not be empty",
            ));
        }

        Ok(())
    }
}

/// JSON body returned by a verifier response endpoint to the wallet after direct post.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectPostResponse {
    /// Optional URI the wallet should redirect the user agent to.
    pub redirect_uri: Option<Url>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp_token_requires_presentations() {
        let token = VpToken(BTreeMap::from([("pid".to_string(), Vec::new())]));

        let err = token.validate().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPresentationResponse);
    }

    #[test]
    fn presentation_response_with_string_token_is_valid() {
        let response = PresentationResponse {
            vp_token: VpToken(BTreeMap::from([(
                "pid".to_string(),
                vec![PresentedCredential::String(
                    "eyJhbGciOiJFUzI1NiJ9...".to_string(),
                )],
            )])),
            id_token: None,
            iss: None,
            state: Some("state-123".to_string()),
        };

        response.validate().unwrap();
    }
}
