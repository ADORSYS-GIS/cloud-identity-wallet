//! Handling for the `redirect_uri:` client identifier prefix per OpenID4VP §5.9.3.
//!
//! Per OpenID4VP §5.9.3, the `redirect_uri:` prefix:
//! - Requires all Verifier metadata parameters to be passed inline via `client_metadata`
//! - Cannot be used for signed Authorization Requests (no trusted key discovery mechanism)
//! - Metadata passed via `client_metadata` is NOT trusted for signature verification
//!
//! This module provides utilities for validating and extracting the redirect URI
//! and metadata from Authorization Requests using this prefix.

use url::Url;

use crate::oid4vp::client_id::{ClientIdPrefix, ParsedClientId};
use crate::oid4vp::metadata::verifier::VerifierMetadata;

#[derive(Debug, thiserror::Error)]
pub enum RedirectUriError {
    #[error("client identifier prefix must be redirect_uri, got: {0}")]
    InvalidClientIdPrefix(String),

    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    #[error("missing required client_metadata for redirect_uri prefix")]
    MissingClientMetadata,

    #[error("invalid verifier metadata: {0}")]
    InvalidMetadata(String),
}

#[derive(Debug)]
pub struct RedirectUriClient {
    redirect_uri: Url,
    metadata: VerifierMetadata,
}

impl RedirectUriClient {
    pub fn parse(
        client_id: &ParsedClientId,
        client_metadata: Option<VerifierMetadata>,
    ) -> Result<Self, RedirectUriError> {
        if client_id.prefix() != Some(ClientIdPrefix::RedirectUri) {
            return Err(RedirectUriError::InvalidClientIdPrefix(format!(
                "{:?}",
                client_id.prefix()
            )));
        }

        let redirect_uri_str = client_id.value();
        let redirect_uri = Url::parse(redirect_uri_str)
            .map_err(|e| RedirectUriError::InvalidRedirectUri(e.to_string()))?;

        let metadata = client_metadata.ok_or(RedirectUriError::MissingClientMetadata)?;

        Ok(Self {
            redirect_uri,
            metadata,
        })
    }

    pub fn redirect_uri(&self) -> &Url {
        &self.redirect_uri
    }

    pub fn metadata(&self) -> &VerifierMetadata {
        &self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_metadata() -> VerifierMetadata {
        serde_json::from_value(json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn parses_valid_redirect_uri_client() {
        let client_id = ParsedClientId::parse("redirect_uri:https://example.com/callback").unwrap();
        let metadata = test_metadata();

        let client = RedirectUriClient::parse(&client_id, Some(metadata)).unwrap();
        assert_eq!(
            client.redirect_uri().as_str(),
            "https://example.com/callback"
        );
    }

    #[test]
    fn rejects_wrong_client_id_prefix() {
        let client_id = ParsedClientId::parse("x509_san_dns:verifier.example.com").unwrap();
        let result = RedirectUriClient::parse(&client_id, Some(test_metadata()));
        assert!(matches!(
            result.unwrap_err(),
            RedirectUriError::InvalidClientIdPrefix(_)
        ));
    }

    #[test]
    fn rejects_missing_client_metadata() {
        let client_id = ParsedClientId::parse("redirect_uri:https://example.com/callback").unwrap();
        let result = RedirectUriClient::parse(&client_id, None);
        assert!(matches!(
            result.unwrap_err(),
            RedirectUriError::MissingClientMetadata
        ));
    }

#[test]
    fn provides_access_to_metadata_fields() {
        let client_id = ParsedClientId::parse("redirect_uri:https://example.com/callback").unwrap();
        let metadata: VerifierMetadata = serde_json::from_value(serde_json::json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256", "ES384"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            },
            "client_name": "Test Verifier"
        }))
        .unwrap();

        let client = RedirectUriClient::parse(&client_id, Some(metadata.clone())).unwrap();
        assert_eq!(client.redirect_uri().as_str(), "https://example.com/callback");
        assert_eq!(client.metadata().client_metadata.client_name.as_deref(), Some("Test Verifier"));
    }
}
