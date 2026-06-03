use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

use crate::errors::{Error, ErrorKind};
use crate::impl_string_enum;
use crate::oid4vp::metadata::verifier::{
    CredentialFormatIdentifier, VpFormatCapability, VpFormatsSupported,
    deserialize_vp_formats_supported, serialize_vp_formats_supported,
};

/// Wallet Metadata for OID4VP.
/// Defined in [OpenID4VP Section 10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WalletPresentationMetadata {
    /// Credential formats the Wallet supports for presentations.
    #[serde(
        rename = "vp_formats_supported",
        serialize_with = "serialize_vp_formats_supported",
        deserialize_with = "deserialize_vp_formats_supported"
    )]
    pub vp_formats_supported: VpFormatsSupported,

    /// Whether the Wallet supports presentation_definition in the request.
    #[serde(rename = "presentation_definition_supported")]
    pub presentation_definition_supported: Option<bool>,

    /// Whether the Wallet supports presentation_definition_uri in the request.
    #[serde(rename = "presentation_definition_uri_supported")]
    pub presentation_definition_uri_supported: Option<bool>,

    /// Client ID prefixes supported by the Wallet.
    #[serde(rename = "client_id_prefixes_supported")]
    pub client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,

    /// JWS signing algorithms supported for Request Objects.
    #[serde(rename = "request_object_signing_alg_values_supported")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// JWE encryption algorithms supported for Request Objects.
    #[serde(rename = "request_object_encryption_alg_values_supported")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    /// JWE encryption methods supported for Request Objects.
    #[serde(rename = "request_object_encryption_enc_values_supported")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    /// Response modes supported by the Wallet.
    #[serde(rename = "response_modes_supported")]
    pub response_modes_supported: Option<Vec<String>>,

    /// Additional metadata parameters from profiles or deployment-specific extensions.
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

/// Client ID prefix values defined by OpenID4VP Section 10.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientIdPrefix {
    /// Redirect URI prefix.
    RedirectUri,
    /// HTTPS prefix.
    Https,
    /// Verifier Attestation prefix (HAIP profile).
    VerifierAttestation,
    /// Extension prefix.
    Other(String),
}

impl_string_enum!(
    ClientIdPrefix,
    {
        RedirectUri => "redirect_uri",
        Https => "https",
        VerifierAttestation => "verifier_attestation"
    },
    "client_id_prefix"
);

impl Default for WalletPresentationMetadata {
    /// Returns sensible defaults for the Wallet's presentation capabilities.
    fn default() -> Self {
        use crate::oid4vp::metadata::verifier::{
            CoseAlgorithmIdentifier, JwtVcJsonFormatCapability, MsoMdocFormatCapability,
            NonEmptyString, SdJwtVcFormatCapability,
        };

        let mut vp_formats_supported = HashMap::new();

        // Helper to create NonEmptyString from known-valid algorithm identifiers.
        // These are hardcoded JOSE algorithm names which are always non-empty.
        fn alg(name: &'static str) -> NonEmptyString {
            NonEmptyString::new(name, "algorithm identifier")
                .expect("JOSE algorithm identifiers are non-empty")
        }

        // vc+sd-jwt format with ES256, ES384, ES512
        vp_formats_supported.insert(
            CredentialFormatIdentifier::DcSdJwt,
            VpFormatCapability::DcSdJwt(SdJwtVcFormatCapability {
                sd_jwt_alg_values: Some(vec![alg("ES256"), alg("ES384"), alg("ES512")]),
                kb_jwt_alg_values: Some(vec![alg("ES256"), alg("ES384"), alg("ES512")]),
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
        vp_formats_supported.insert(
            CredentialFormatIdentifier::JwtVcJson,
            VpFormatCapability::JwtVcJson(JwtVcJsonFormatCapability {
                alg_values: Some(vec![alg("ES256"), alg("ES384"), alg("ES512")]),
            }),
        );

        Self {
            vp_formats_supported,
            presentation_definition_supported: Some(true),
            presentation_definition_uri_supported: Some(true),
            client_id_prefixes_supported: Some(vec![
                ClientIdPrefix::RedirectUri,
                ClientIdPrefix::Https,
            ]),
            request_object_signing_alg_values_supported: Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string(),
            ]),
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            response_modes_supported: Some(vec![
                "direct_post".to_string(),
                "direct_post.jwt".to_string(),
            ]),
            extra_fields: HashMap::new(),
        }
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

impl WalletPresentationMetadata {
    /// Validates the Wallet Presentation Metadata.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        // Validate that vp_formats_supported is not empty
        if self.vp_formats_supported.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidAuthorizationServerMetadata,
                "vp_formats_supported must contain at least one entry",
            ));
        }

        Ok(())
    }
}

#[skip_serializing_none]
#[derive(Debug, Deserialize)]
struct WalletPresentationMetadataUnchecked {
    #[serde(
        rename = "vp_formats_supported",
        deserialize_with = "deserialize_vp_formats_supported"
    )]
    vp_formats_supported: VpFormatsSupported,
    #[serde(rename = "presentation_definition_supported")]
    presentation_definition_supported: Option<bool>,
    #[serde(rename = "presentation_definition_uri_supported")]
    presentation_definition_uri_supported: Option<bool>,
    #[serde(rename = "client_id_prefixes_supported")]
    client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,
    #[serde(rename = "request_object_signing_alg_values_supported")]
    request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(rename = "request_object_encryption_alg_values_supported")]
    request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(rename = "request_object_encryption_enc_values_supported")]
    request_object_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(rename = "response_modes_supported")]
    response_modes_supported: Option<Vec<String>>,
    #[serde(flatten)]
    extra_fields: HashMap<String, serde_json::Value>,
}

impl WalletPresentationMetadataUnchecked {
    fn into_metadata(self) -> WalletPresentationMetadata {
        WalletPresentationMetadata {
            vp_formats_supported: self.vp_formats_supported,
            presentation_definition_supported: self.presentation_definition_supported,
            presentation_definition_uri_supported: self.presentation_definition_uri_supported,
            client_id_prefixes_supported: self.client_id_prefixes_supported,
            request_object_signing_alg_values_supported: self
                .request_object_signing_alg_values_supported,
            request_object_encryption_alg_values_supported: self
                .request_object_encryption_alg_values_supported,
            request_object_encryption_enc_values_supported: self
                .request_object_encryption_enc_values_supported,
            response_modes_supported: self.response_modes_supported,
            extra_fields: self.extra_fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_wallet_presentation_metadata() {
        let metadata = WalletPresentationMetadata::default();

        // Verify vp_formats_supported contains all expected formats
        assert!(
            metadata
                .vp_formats_supported
                .contains_key(&CredentialFormatIdentifier::DcSdJwt)
        );
        assert!(
            metadata
                .vp_formats_supported
                .contains_key(&CredentialFormatIdentifier::MsoMdoc)
        );
        assert!(
            metadata
                .vp_formats_supported
                .contains_key(&CredentialFormatIdentifier::JwtVcJson)
        );

        // Verify vc+sd-jwt format has correct algorithm fields
        let sd_jwt_format = metadata
            .vp_formats_supported
            .get(&CredentialFormatIdentifier::DcSdJwt)
            .unwrap();
        match sd_jwt_format {
            VpFormatCapability::DcSdJwt(cap) => {
                assert_eq!(cap.sd_jwt_alg_values.as_ref().map(|v| v.len()), Some(3));
                assert_eq!(cap.kb_jwt_alg_values.as_ref().map(|v| v.len()), Some(3));
            }
            _ => panic!("Expected DcSdJwt format capability"),
        }

        // Verify mso_mdoc format has correct algorithm fields
        let mdoc_format = metadata
            .vp_formats_supported
            .get(&CredentialFormatIdentifier::MsoMdoc)
            .unwrap();
        match mdoc_format {
            VpFormatCapability::MsoMdoc(cap) => {
                assert_eq!(cap.issuerauth_alg_values.as_ref().map(|v| v.len()), Some(3));
                assert_eq!(cap.deviceauth_alg_values.as_ref().map(|v| v.len()), Some(3));
            }
            _ => panic!("Expected MsoMdoc format capability"),
        }

        // Verify jwt_vc_json format has correct algorithm fields
        let jwt_vc_format = metadata
            .vp_formats_supported
            .get(&CredentialFormatIdentifier::JwtVcJson)
            .unwrap();
        match jwt_vc_format {
            VpFormatCapability::JwtVcJson(cap) => {
                assert_eq!(cap.alg_values.as_ref().map(|v| v.len()), Some(3));
            }
            _ => panic!("Expected JwtVcJson format capability"),
        }

        // Verify presentation_definition support
        assert_eq!(metadata.presentation_definition_supported, Some(true));
        assert_eq!(metadata.presentation_definition_uri_supported, Some(true));

        // Verify client_id_prefixes_supported
        assert_eq!(
            metadata.client_id_prefixes_supported,
            Some(vec![ClientIdPrefix::RedirectUri, ClientIdPrefix::Https])
        );

        // Verify request_object_signing_alg_values_supported
        assert_eq!(
            metadata.request_object_signing_alg_values_supported,
            Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string()
            ])
        );

        // Verify response_modes_supported
        assert_eq!(
            metadata.response_modes_supported,
            Some(vec![
                "direct_post".to_string(),
                "direct_post.jwt".to_string()
            ])
        );

        // Verify optional fields are None by default
        assert!(
            metadata
                .request_object_encryption_alg_values_supported
                .is_none()
        );
        assert!(
            metadata
                .request_object_encryption_enc_values_supported
                .is_none()
        );

        // Verify extra_fields is empty
        assert!(metadata.extra_fields.is_empty());
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = WalletPresentationMetadata::default();
        // Serialize to JSON
        let json = serde_json::to_string(&original).expect("Failed to serialize");
        // Deserialize back
        let deserialized: WalletPresentationMetadata =
            serde_json::from_str(&json).expect("Failed to deserialize");
        // Verify round-trip fidelity
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_deserialization() {
        let json = r#"{
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            },
            "presentation_definition_supported": true,
            "client_id_prefixes_supported": ["redirect_uri"],
            "response_modes_supported": ["direct_post"]
        }"#;
        let metadata: WalletPresentationMetadata =
            serde_json::from_str(json).expect("Failed to parse JSON");
        assert!(
            metadata
                .vp_formats_supported
                .contains_key(&CredentialFormatIdentifier::DcSdJwt)
        );
        assert_eq!(metadata.presentation_definition_supported, Some(true));
        assert_eq!(
            metadata.client_id_prefixes_supported,
            Some(vec![ClientIdPrefix::RedirectUri])
        );
    }

    #[test]
    fn test_serde_skips_none_fields() {
        let metadata = WalletPresentationMetadata {
            vp_formats_supported: HashMap::new(),
            presentation_definition_supported: None,
            presentation_definition_uri_supported: None,
            client_id_prefixes_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            response_modes_supported: None,
            extra_fields: HashMap::new(),
        };
        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        // None fields should be skipped in serialization
        assert!(!json.contains("presentation_definition_supported"));
        assert!(!json.contains("presentation_definition_uri_supported"));
        assert!(!json.contains("client_id_prefixes_supported"));
        assert!(!json.contains("request_object_signing_alg_values_supported"));
        assert!(!json.contains("request_object_encryption_alg_values_supported"));
        assert!(!json.contains("request_object_encryption_enc_values_supported"));
        assert!(!json.contains("response_modes_supported"));
    }

    #[test]
    fn test_extra_fields_roundtrip() {
        let mut metadata = WalletPresentationMetadata::default();
        metadata.extra_fields.insert(
            "custom_field".to_string(),
            serde_json::json!("custom_value"),
        );
        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        let deserialized: WalletPresentationMetadata =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(
            deserialized.extra_fields.get("custom_field"),
            Some(&serde_json::json!("custom_value"))
        );
    }

    #[test]
    fn test_client_id_prefix_serde() {
        // Test serialization
        let prefix = ClientIdPrefix::RedirectUri;
        let json = serde_json::to_string(&prefix).expect("Failed to serialize");
        assert_eq!(json, "\"redirect_uri\"");

        let prefix = ClientIdPrefix::Https;
        let json = serde_json::to_string(&prefix).expect("Failed to serialize");
        assert_eq!(json, "\"https\"");

        // Test deserialization
        let prefix: ClientIdPrefix =
            serde_json::from_str("\"redirect_uri\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::RedirectUri);

        let prefix: ClientIdPrefix =
            serde_json::from_str("\"https\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::Https);

        // Test extension prefix
        let prefix: ClientIdPrefix =
            serde_json::from_str("\"custom_prefix\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::Other("custom_prefix".to_string()));
    }

    #[test]
    fn test_rejects_empty_vp_formats_supported() {
        let metadata = WalletPresentationMetadata {
            vp_formats_supported: HashMap::new(),
            presentation_definition_supported: None,
            presentation_definition_uri_supported: None,
            client_id_prefixes_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            response_modes_supported: None,
            extra_fields: HashMap::new(),
        };
        let err = metadata.validate().unwrap_err();
        assert!(err.to_string().contains("vp_formats_supported"));
    }
}
