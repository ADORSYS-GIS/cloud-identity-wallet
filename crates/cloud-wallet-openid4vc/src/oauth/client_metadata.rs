//! OAuth 2.0 Dynamic Client Registration metadata.
//!
//! These models cover the client metadata parameters defined by [RFC 7591].
//!
//! [RFC 7591]: https://datatracker.ietf.org/doc/html/rfc7591

use std::collections::HashMap;

use cloud_wallet_crypto::jwk::JwkSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;

use crate::errors::{Error, ErrorKind};
use crate::impl_string_enum;
use crate::utils::{validate_non_empty_array, validate_non_empty_string_array};

/// Additional RFC 7591 client metadata fields not explicitly modeled by this crate.
pub type AdditionalClientMetadata = HashMap<String, Value>;

/// OAuth 2.0 Dynamic Client Registration metadata from RFC 7591 Section 2.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// OAuth redirect URIs for the client.
    pub redirect_uris: Option<Vec<Url>>,

    /// Requested authentication method for the token endpoint.
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,

    /// OAuth grant types the client can use.
    pub grant_types: Option<Vec<GrantType>>,

    /// OAuth response types the client can use.
    pub response_types: Option<Vec<ResponseType>>,

    /// Space-separated OAuth scope values.
    pub scope: Option<String>,

    /// Human-readable client name.
    pub client_name: Option<String>,

    /// URL of a web page providing information about the client.
    pub client_uri: Option<Url>,

    /// URL of the client logo.
    pub logo_uri: Option<Url>,

    /// Contact strings for people responsible for the client.
    pub contacts: Option<Vec<String>>,

    /// URL of the client terms of service.
    pub tos_uri: Option<Url>,

    /// URL of the client policy document.
    pub policy_uri: Option<Url>,

    /// URL of the client's JSON Web Key Set.
    pub jwks_uri: Option<Url>,

    /// Inline client JSON Web Key Set.
    pub jwks: Option<JwkSet>,

    /// Stable software identifier assigned by the client developer.
    pub software_id: Option<String>,

    /// Version identifier for the client software.
    pub software_version: Option<String>,

    /// Additional RFC 7591 client metadata fields not explicitly modeled by this crate.
    #[serde(flatten)]
    pub additional: AdditionalClientMetadata,
}

impl ClientMetadata {
    /// Validates RFC 7591 structural requirements that can be checked locally.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        if self.jwks.is_some() && self.jwks_uri.is_some() {
            return invalid("jwks and jwks_uri must not both be present");
        }

        if let Some(redirect_uris) = &self.redirect_uris {
            validate_non_empty_array(redirect_uris, "redirect_uris")?;
        }
        if let Some(grant_types) = &self.grant_types {
            validate_non_empty_array(grant_types, "grant_types")?;
        }
        if let Some(response_types) = &self.response_types {
            validate_non_empty_array(response_types, "response_types")?;
        }
        if let Some(contacts) = &self.contacts {
            validate_non_empty_string_array(contacts, "contacts")?;
        }
        Ok(())
    }
}

/// RFC 7591 token endpoint authentication methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretPost,
    ClientSecretBasic,
    Other(String),
}

impl_string_enum!(
    TokenEndpointAuthMethod,
    {
        None => "none",
        ClientSecretPost => "client_secret_post",
        ClientSecretBasic => "client_secret_basic"
    },
    "token_endpoint_auth_method"
);

/// OAuth grant type values registered by RFC 7591, with extension support.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantType {
    AuthorizationCode,
    Implicit,
    Password,
    ClientCredentials,
    RefreshToken,
    JwtBearer,
    Saml2Bearer,
    Other(String),
}

impl_string_enum!(
    GrantType,
    {
        AuthorizationCode => "authorization_code",
        Implicit => "implicit",
        Password => "password",
        ClientCredentials => "client_credentials",
        RefreshToken => "refresh_token",
        JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
        Saml2Bearer => "urn:ietf:params:oauth:grant-type:saml2-bearer"
    },
    "grant_type"
);

/// OAuth response type values from RFC 7591 plus OpenID4VP's `vp_token`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResponseType {
    Code,
    Token,
    VpToken,
    Other(String),
}

impl_string_enum!(
    ResponseType,
    {
        Code => "code",
        Token => "token",
        VpToken => "vp_token"
    },
    "response_type"
);

fn invalid<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::message(
        ErrorKind::InvalidClientMetadata,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deserializes_registered_client_metadata_values() {
        let metadata: ClientMetadata = serde_json::from_value(json!({
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"]
        }))
        .expect("valid client metadata");

        assert_eq!(
            metadata.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::ClientSecretPost)
        );
        assert_eq!(
            metadata.grant_types.as_deref(),
            Some(&[GrantType::AuthorizationCode, GrantType::RefreshToken][..])
        );
        assert_eq!(
            metadata.response_types.as_deref(),
            Some(&[ResponseType::Code][..])
        );
    }

    #[test]
    fn preserves_extension_client_metadata_values() {
        let metadata: ClientMetadata = serde_json::from_value(json!({
            "token_endpoint_auth_method": "private_key_jwt",
            "grant_types": ["urn:example:grant"],
            "response_types": ["code id_token"]
        }))
        .expect("extension values are allowed by registries and profiles");

        assert_eq!(
            metadata.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::Other(
                "private_key_jwt".to_string()
            ))
        );
        assert_eq!(
            metadata.grant_types.as_deref(),
            Some(&[GrantType::Other("urn:example:grant".to_string())][..])
        );
        assert_eq!(
            metadata.response_types.as_deref(),
            Some(&[ResponseType::Other("code id_token".to_string())][..])
        );
    }

    #[test]
    fn rejects_empty_registered_value_strings() {
        let err = serde_json::from_value::<ClientMetadata>(json!({
            "token_endpoint_auth_method": ""
        }))
        .unwrap_err();

        assert!(err.to_string().contains("token_endpoint_auth_method"));
    }

    #[test]
    fn validates_jwks_and_jwks_uri_are_mutually_exclusive() {
        let metadata: ClientMetadata = serde_json::from_value(json!({
            "jwks_uri": "https://client.example.org/jwks.json",
            "jwks": {"keys": []}
        }))
        .expect("structural JSON is valid");

        let err = metadata.validate().unwrap_err();

        assert!(err.to_string().contains("jwks and jwks_uri"));
    }
}
