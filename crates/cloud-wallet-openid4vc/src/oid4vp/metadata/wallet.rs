use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

use crate::errors::{Error, ErrorKind};
use crate::impl_string_enum;
use crate::oid4vci::metadata::AuthorizationServerMetadata;
use crate::oid4vp::metadata::{
    CredentialFormatIdentifier, VpFormatCapability, VpFormatsSupported,
    deserialize_vp_formats_supported,
};

/// Wallet Metadata for OID4VP.
///
/// Per [OpenID4VP Section 10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10),
/// Wallet Metadata is OAuth 2.0 Authorization Server Metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html))
/// plus the OID4VP-specific extension parameters (`vp_formats_supported`, `client_id_prefixes_supported`).
///
/// This struct composes the base [`AuthorizationServerMetadata`] with the OID4VP-specific
/// fields to represent a complete, spec-compliant Wallet Metadata document that can be
/// serialized and published at the Wallet's metadata endpoint.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WalletPresentationMetadata {
    #[serde(flatten)]
    pub authorization_server_metadata: AuthorizationServerMetadata,

    pub vp_formats_supported: VpFormatsSupported,

    pub client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,
}

/// Client ID prefix values defined by OpenID4VP Section 10.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientIdPrefix {
    /// Pre-registered behavior (when no Client Identifier Prefix is used).
    PreRegistered,
    /// Redirect URI prefix.
    RedirectUri,
    /// OpenID Federation prefix.
    OpenidFederation,
    /// Verifier Attestation prefix.
    VerifierAttestation,
    /// Decentralized Identifier prefix.
    DecentralizedIdentifier,
    /// X.509 SAN DNS prefix.
    X509SanDns,
    /// X.509 Hash prefix.
    X509Hash,
    /// Extension prefix.
    Other(String),
}

impl_string_enum!(
    ClientIdPrefix,
    {
        PreRegistered => "pre-registered",
        RedirectUri => "redirect_uri",
        OpenidFederation => "openid_federation",
        VerifierAttestation => "verifier_attestation",
        DecentralizedIdentifier => "decentralized_identifier",
        X509SanDns => "x509_san_dns",
        X509Hash => "x509_hash"
    },
    "client_id_prefix"
);

impl WalletPresentationMetadata {
    pub fn new(
        authorization_server_metadata: AuthorizationServerMetadata,
        vp_formats_supported: VpFormatsSupported,
    ) -> Self {
        Self {
            authorization_server_metadata,
            vp_formats_supported,
            client_id_prefixes_supported: None,
        }
    }

    /// Returns sensible defaults for the Wallet's presentation capabilities (`vp_formats_supported`).
    pub fn default_vp_formats() -> VpFormatsSupported {
        use crate::oid4vp::metadata::{
            CoseAlgorithmIdentifier, JwtVcJsonFormatCapability, MsoMdocFormatCapability,
            NonEmptyString, SdJwtVcFormatCapability,
        };

        let mut vp_formats_supported = HashMap::new();

        // Compile-time safe constants for algorithm identifiers
        let es256 = NonEmptyString::from_static("ES256");
        let es384 = NonEmptyString::from_static("ES384");
        let es512 = NonEmptyString::from_static("ES512");

        // vc+sd-jwt format with ES256, ES384, ES512
        let sd_jwt_algs = Some(vec![es256.clone(), es384.clone(), es512.clone()]);
        vp_formats_supported.insert(
            CredentialFormatIdentifier::DcSdJwt,
            VpFormatCapability::DcSdJwt(SdJwtVcFormatCapability {
                sd_jwt_alg_values: sd_jwt_algs.clone(),
                kb_jwt_alg_values: sd_jwt_algs,
            }),
        );

        // mso_mdoc format with ES256, ES384, ES512 (COSE algorithm identifiers)
        vp_formats_supported.insert(
            CredentialFormatIdentifier::MsoMdoc,
            VpFormatCapability::MsoMdoc(MsoMdocFormatCapability {
                issuerauth_alg_values: Some(vec![
                    CoseAlgorithmIdentifier::Integer(-7),
                    CoseAlgorithmIdentifier::Integer(-35),
                    CoseAlgorithmIdentifier::Integer(-36),
                ]),
                deviceauth_alg_values: Some(vec![
                    CoseAlgorithmIdentifier::Integer(-7),
                    CoseAlgorithmIdentifier::Integer(-35),
                    CoseAlgorithmIdentifier::Integer(-36),
                ]),
            }),
        );

        // jwt_vc_json format with ES256, ES384, ES512
        let jwt_vc_algs = Some(vec![es256, es384, es512]);
        vp_formats_supported.insert(
            CredentialFormatIdentifier::JwtVcJson,
            VpFormatCapability::JwtVcJson(JwtVcJsonFormatCapability {
                alg_values: jwt_vc_algs,
            }),
        );

        vp_formats_supported
    }

    /// Returns sensible defaults for `client_id_prefixes_supported`.
    pub fn default_client_id_prefixes() -> Option<Vec<ClientIdPrefix>> {
        Some(vec![
            ClientIdPrefix::PreRegistered,
            ClientIdPrefix::RedirectUri,
        ])
    }

    /// Validates the Wallet Presentation Metadata.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        // Validate the base Authorization Server Metadata
        self.authorization_server_metadata.validate().map_err(|e| {
            Error::message(
                ErrorKind::InvalidWalletMetadata,
                format!("authorization server metadata validation failed: {e}"),
            )
        })?;

        // Validate that vp_formats_supported is not empty (OID4VP Section 10.1)
        if self.vp_formats_supported.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidWalletMetadata,
                "vp_formats_supported must contain at least one entry",
            ));
        }

        // Validate individual format capabilities
        for capability in self.vp_formats_supported.values() {
            capability.validate().map_err(|e| {
                Error::message(
                    ErrorKind::InvalidWalletMetadata,
                    format!("vp_formats_supported validation failed: {e}"),
                )
            })?;
        }

        // Validate client_id_prefixes_supported is non-empty if present (OID4VP Section 10.1)
        if let Some(prefixes) = &self.client_id_prefixes_supported
            && prefixes.is_empty()
        {
            return Err(Error::message(
                ErrorKind::InvalidWalletMetadata,
                "client_id_prefixes_supported must be a non-empty array",
            ));
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for WalletPresentationMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let metadata =
            WalletPresentationMetadataUnchecked::deserialize(deserializer)?.into_metadata();
        metadata.validate().map_err(DeError::custom)?;
        Ok(metadata)
    }
}

#[skip_serializing_none]
#[derive(Debug, Deserialize)]
struct WalletPresentationMetadataUnchecked {
    #[serde(flatten)]
    authorization_server_metadata: AuthorizationServerMetadata,
    #[serde(deserialize_with = "deserialize_vp_formats_supported")]
    vp_formats_supported: VpFormatsSupported,
    client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,
}

impl WalletPresentationMetadataUnchecked {
    fn into_metadata(self) -> WalletPresentationMetadata {
        WalletPresentationMetadata {
            authorization_server_metadata: self.authorization_server_metadata,
            vp_formats_supported: self.vp_formats_supported,
            client_id_prefixes_supported: self.client_id_prefixes_supported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid4vci::metadata::AuthorizationServerMetadata;

    fn minimal_as_metadata() -> AuthorizationServerMetadata {
        use url::Url;

        fn parse_url(url: &str) -> Option<Url> {
            Url::parse(url).ok()
        }

        AuthorizationServerMetadata {
            issuer: match parse_url("https://wallet.example.com") {
                Some(url) => url,
                None => panic!("Invalid issuer URL in test data"),
            },
            authorization_endpoint: parse_url("https://wallet.example.com/authorize"),
            token_endpoint: parse_url("https://wallet.example.com/token"),
            jwks_uri: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: Some(vec!["vp_token".to_string()]),
            response_modes_supported: None,
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            token_endpoint_auth_signing_alg_values_supported: None,
            service_documentation: None,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: None,
            revocation_endpoint_auth_methods_supported: None,
            revocation_endpoint_auth_signing_alg_values_supported: None,
            introspection_endpoint: None,
            introspection_endpoint_auth_methods_supported: None,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            code_challenge_methods_supported: None,
            pushed_authorization_request_endpoint: None,
            require_pushed_authorization_requests: None,
            pre_authorized_grant_anonymous_access_supported: None,
            extra_fields: HashMap::new(),
        }
    }

    /// Tests that default VP formats contain expected formats with correct algorithms.
    #[test]
    fn defaults_contain_expected_formats_and_algorithms() {
        let vp_formats = WalletPresentationMetadata::default_vp_formats();

        assert_eq!(vp_formats.len(), 3);
        assert!(vp_formats.contains_key(&CredentialFormatIdentifier::DcSdJwt));
        assert!(vp_formats.contains_key(&CredentialFormatIdentifier::MsoMdoc));
        assert!(vp_formats.contains_key(&CredentialFormatIdentifier::JwtVcJson));

        // Verify dc+sd-jwt format has ES256, ES384, ES512
        match vp_formats.get(&CredentialFormatIdentifier::DcSdJwt) {
            Some(VpFormatCapability::DcSdJwt(cap)) => {
                assert_eq!(cap.sd_jwt_alg_values.as_ref().map(|v| v.len()), Some(3));
            }
            _ => panic!("Expected DcSdJwt format capability"),
        }
    }

    /// Tests complete spec-compliant metadata document serialization roundtrip.
    #[test]
    fn complete_metadata_roundtrip() {
        let json = r#"{
            "issuer": "https://wallet.example.com",
            "authorization_endpoint": "https://wallet.example.com/authorize",
            "token_endpoint": "https://wallet.example.com/token",
            "response_types_supported": ["vp_token"],
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                },
                "mso_mdoc": {
                    "issuerauth_alg_values": [-7],
                    "deviceauth_alg_values": [-7]
                }
            },
            "client_id_prefixes_supported": ["redirect_uri", "pre-registered"]
        }"#;

        let metadata: WalletPresentationMetadata = match serde_json::from_str(json) {
            Ok(m) => m,
            Err(e) => panic!("Failed to parse JSON: {}", e),
        };

        // Verify base AS fields
        assert_eq!(
            metadata.authorization_server_metadata.issuer.as_str(),
            "https://wallet.example.com/"
        );

        // Verify OID4VP fields
        assert_eq!(metadata.vp_formats_supported.len(), 2);
        match &metadata.client_id_prefixes_supported {
            Some(prefixes) => {
                assert!(prefixes.contains(&ClientIdPrefix::RedirectUri));
            }
            None => panic!("Expected client_id_prefixes_supported"),
        }

        // Validate and serialize back
        assert!(metadata.validate().is_ok());
        match serde_json::to_string(&metadata) {
            Ok(_) => {} // serialization succeeded
            Err(e) => panic!("Failed to serialize: {}", e),
        }
    }

    /// Tests that validation rejects invalid metadata.
    #[test]
    fn validation_rejects_invalid_metadata() {
        // Empty vp_formats_supported should fail
        let as_metadata = minimal_as_metadata();
        let metadata = WalletPresentationMetadata {
            authorization_server_metadata: as_metadata,
            vp_formats_supported: HashMap::new(),
            client_id_prefixes_supported: None,
        };
        match metadata.validate() {
            Err(e) => {
                assert!(e.to_string().contains("vp_formats_supported"));
                assert_eq!(e.kind(), ErrorKind::InvalidWalletMetadata);
            }
            Ok(_) => panic!("Expected validation to fail for empty vp_formats_supported"),
        }

        // Empty client_id_prefixes_supported should fail
        let as_metadata = minimal_as_metadata();
        let metadata = WalletPresentationMetadata {
            authorization_server_metadata: as_metadata,
            vp_formats_supported: WalletPresentationMetadata::default_vp_formats(),
            client_id_prefixes_supported: Some(vec![]),
        };
        match metadata.validate() {
            Err(e) => {
                assert!(e.to_string().contains("client_id_prefixes_supported"));
            }
            Ok(_) => panic!("Expected validation to fail for empty client_id_prefixes_supported"),
        }

        // Invalid AS metadata (http issuer) should fail
        use url::Url;
        let mut as_metadata = minimal_as_metadata();
        as_metadata.issuer = match Url::parse("http://wallet.example.com") {
            Ok(url) => url,
            Err(e) => panic!("Failed to parse URL: {}", e),
        };
        let metadata = WalletPresentationMetadata {
            authorization_server_metadata: as_metadata,
            vp_formats_supported: WalletPresentationMetadata::default_vp_formats(),
            client_id_prefixes_supported: None,
        };
        match metadata.validate() {
            Err(e) => {
                assert!(e.to_string().contains("authorization server metadata"));
            }
            Ok(_) => panic!("Expected validation to fail for http issuer"),
        }
    }

    /// Tests ClientIdPrefix serialization and deserialization.
    #[test]
    fn client_id_prefix_serde() {
        let test_cases = [
            (ClientIdPrefix::PreRegistered, "\"pre-registered\""),
            (ClientIdPrefix::RedirectUri, "\"redirect_uri\""),
            (ClientIdPrefix::OpenidFederation, "\"openid_federation\""),
            (
                ClientIdPrefix::VerifierAttestation,
                "\"verifier_attestation\"",
            ),
            (
                ClientIdPrefix::DecentralizedIdentifier,
                "\"decentralized_identifier\"",
            ),
            (ClientIdPrefix::X509SanDns, "\"x509_san_dns\""),
            (ClientIdPrefix::X509Hash, "\"x509_hash\""),
        ];

        for (prefix, expected) in test_cases {
            match serde_json::to_string(&prefix) {
                Ok(json) => assert_eq!(json, expected),
                Err(e) => panic!("Failed to serialize: {}", e),
            }
        }

        // Extension prefix deserializes to Other
        match serde_json::from_str::<ClientIdPrefix>("\"custom_prefix\"") {
            Ok(prefix) => {
                assert_eq!(prefix, ClientIdPrefix::Other("custom_prefix".to_string()));
            }
            Err(e) => panic!("Failed to deserialize: {}", e),
        }
    }
}
