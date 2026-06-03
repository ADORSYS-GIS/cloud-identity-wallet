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
    #[serde(
        rename = "vp_formats_supported",
        serialize_with = "serialize_vp_formats_supported",
        deserialize_with = "deserialize_vp_formats_supported"
    )]
    pub vp_formats_supported: VpFormatsSupported,

    #[serde(rename = "client_id_prefixes_supported")]
    pub client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,

    /// Additional metadata parameters from profiles or deployment-specific extensions.
    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
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

impl Default for WalletPresentationMetadata {
    /// Returns sensible defaults for the Wallet's presentation capabilities.
    fn default() -> Self {
        use crate::oid4vp::metadata::verifier::{
            CoseAlgorithmIdentifier, JwtVcJsonFormatCapability, MsoMdocFormatCapability,
            NonEmptyString, SdJwtVcFormatCapability,
        };

        let mut vp_formats_supported = HashMap::new();

        let es256 = NonEmptyString::new("ES256", "algorithm identifier");
        let es384 = NonEmptyString::new("ES384", "algorithm identifier");
        let es512 = NonEmptyString::new("ES512", "algorithm identifier");

        // vc+sd-jwt format with ES256, ES384, ES512
        let sd_jwt_algs = match (&es256, &es384, &es512) {
            (Ok(a), Ok(b), Ok(c)) => Some(vec![a.clone(), b.clone(), c.clone()]),
            _ => None,
        };
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
        let jwt_vc_algs = match (es256, es384, es512) {
            (Ok(a), Ok(b), Ok(c)) => Some(vec![a, b, c]),
            _ => None,
        };
        vp_formats_supported.insert(
            CredentialFormatIdentifier::JwtVcJson,
            VpFormatCapability::JwtVcJson(JwtVcJsonFormatCapability {
                alg_values: jwt_vc_algs,
            }),
        );

        Self {
            vp_formats_supported,
            client_id_prefixes_supported: Some(vec![
                ClientIdPrefix::PreRegistered,
                ClientIdPrefix::RedirectUri,
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
    #[serde(rename = "client_id_prefixes_supported")]
    client_id_prefixes_supported: Option<Vec<ClientIdPrefix>>,
    #[serde(flatten)]
    extra_fields: HashMap<String, serde_json::Value>,
}

impl WalletPresentationMetadataUnchecked {
    fn into_metadata(self) -> WalletPresentationMetadata {
        WalletPresentationMetadata {
            vp_formats_supported: self.vp_formats_supported,
            client_id_prefixes_supported: self.client_id_prefixes_supported,
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

        // Verify client_id_prefixes_supported - spec-compliant defaults
        assert_eq!(
            metadata.client_id_prefixes_supported,
            Some(vec![
                ClientIdPrefix::PreRegistered,
                ClientIdPrefix::RedirectUri
            ])
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
            "client_id_prefixes_supported": ["redirect_uri", "pre-registered"]
        }"#;
        let metadata: WalletPresentationMetadata =
            serde_json::from_str(json).expect("Failed to parse JSON");
        assert!(
            metadata
                .vp_formats_supported
                .contains_key(&CredentialFormatIdentifier::DcSdJwt)
        );
        assert_eq!(
            metadata.client_id_prefixes_supported,
            Some(vec![
                ClientIdPrefix::RedirectUri,
                ClientIdPrefix::PreRegistered
            ])
        );
    }

    #[test]
    fn test_serde_skips_none_fields() {
        // Create a minimal metadata with empty vp_formats_supported and None client_id_prefixes_supported
        // Note: This won't pass validation but we're only testing serialization behavior
        let mut vp_formats_supported = HashMap::new();
        vp_formats_supported.insert(
            CredentialFormatIdentifier::DcSdJwt,
            VpFormatCapability::DcSdJwt(Default::default()),
        );
        let metadata = WalletPresentationMetadata {
            vp_formats_supported,
            client_id_prefixes_supported: None,
            extra_fields: HashMap::new(),
        };
        let json = serde_json::to_string(&metadata).expect("Failed to serialize");
        // None fields should be skipped in serialization
        assert!(!json.contains("client_id_prefixes_supported"));
        // vp_formats_supported should be present since it's required
        assert!(json.contains("vp_formats_supported"));
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
        // Test serialization of all spec-defined prefixes
        let test_cases = vec![
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
            let json = serde_json::to_string(&prefix).expect("Failed to serialize");
            assert_eq!(json, expected);
        }

        // Test deserialization
        let prefix: ClientIdPrefix =
            serde_json::from_str("\"redirect_uri\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::RedirectUri);

        let prefix: ClientIdPrefix =
            serde_json::from_str("\"pre-registered\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::PreRegistered);

        let prefix: ClientIdPrefix =
            serde_json::from_str("\"verifier_attestation\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::VerifierAttestation);

        // Test extension prefix
        let prefix: ClientIdPrefix =
            serde_json::from_str("\"custom_prefix\"").expect("Failed to deserialize");
        assert_eq!(prefix, ClientIdPrefix::Other("custom_prefix".to_string()));
    }

    #[test]
    fn test_rejects_empty_vp_formats_supported() {
        let metadata = WalletPresentationMetadata {
            vp_formats_supported: HashMap::new(),
            client_id_prefixes_supported: None,
            extra_fields: HashMap::new(),
        };
        let err = metadata.validate().unwrap_err();
        assert!(err.to_string().contains("vp_formats_supported"));
    }

    #[test]
    fn test_supports_all_spec_client_id_prefixes() {
        // Verify all spec-defined prefixes can be deserialized
        let prefixes_json = r#"[
            "pre-registered",
            "redirect_uri",
            "openid_federation",
            "verifier_attestation",
            "decentralized_identifier",
            "x509_san_dns",
            "x509_hash"
        ]"#;

        let prefixes: Vec<ClientIdPrefix> =
            serde_json::from_str(prefixes_json).expect("Failed to deserialize prefixes");

        assert_eq!(prefixes.len(), 7);
        assert!(prefixes.contains(&ClientIdPrefix::PreRegistered));
        assert!(prefixes.contains(&ClientIdPrefix::RedirectUri));
        assert!(prefixes.contains(&ClientIdPrefix::OpenidFederation));
        assert!(prefixes.contains(&ClientIdPrefix::VerifierAttestation));
        assert!(prefixes.contains(&ClientIdPrefix::DecentralizedIdentifier));
        assert!(prefixes.contains(&ClientIdPrefix::X509SanDns));
        assert!(prefixes.contains(&ClientIdPrefix::X509Hash));
    }
}
