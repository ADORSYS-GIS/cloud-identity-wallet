use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
/// Wallet Metadata for OID4VP.
/// Defined in [OpenID4VP Section 10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPresentationMetadata {
    #[serde(rename = "vp_formats_supported")]
    pub vp_formats_supported: HashMap<String, VpFormat>,

    #[serde(rename = "presentation_definition_supported")]
    pub presentation_definition_supported: Option<bool>,

    #[serde(rename = "presentation_definition_uri_supported")]
    pub presentation_definition_uri_supported: Option<bool>,

    #[serde(rename = "client_id_schemes_supported")]
    pub client_id_schemes_supported: Option<Vec<String>>,

    #[serde(rename = "request_object_signing_alg_values_supported")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(rename = "request_object_encryption_alg_values_supported")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    #[serde(rename = "request_object_encryption_enc_values_supported")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    #[serde(rename = "response_modes_supported")]
    pub response_modes_supported: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra_fields: HashMap<String, serde_json::Value>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpFormat {
    /// For `vc+sd-jwt` format: SD-JWT signature algorithms supported.
    #[serde(rename = "sd-jwt_alg_values")]
    pub sd_jwt_alg_values: Option<Vec<String>>,
    /// For `vc+sd-jwt` format: Key Binding JWT algorithms supported.
    #[serde(rename = "kb-jwt_alg_values")]
    pub kb_jwt_alg_values: Option<Vec<String>>,
    /// For `mso_mdoc` and `jwt_vc_json` formats: Signature algorithms supported.
    #[serde(rename = "alg_values")]
    pub alg_values: Option<Vec<String>>,
}
impl Default for WalletPresentationMetadata {
    /// Returns sensible defaults for the Wallet's presentation capabilities.
    fn default() -> Self {
        let mut vp_formats_supported = HashMap::new();
        // vc+sd-jwt format with ES256, ES384, ES512
        vp_formats_supported.insert(
            "vc+sd-jwt".to_string(),
            VpFormat {
                sd_jwt_alg_values: Some(vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ]),
                kb_jwt_alg_values: Some(vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ]),
                alg_values: None,
            },
        );
        // mso_mdoc format with ES256, ES384, ES512
        vp_formats_supported.insert(
            "mso_mdoc".to_string(),
            VpFormat {
                sd_jwt_alg_values: None,
                kb_jwt_alg_values: None,
                alg_values: Some(vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ]),
            },
        );
        // jwt_vc_json format with ES256, ES384, ES512
        vp_formats_supported.insert(
            "jwt_vc_json".to_string(),
            VpFormat {
                sd_jwt_alg_values: None,
                kb_jwt_alg_values: None,
                alg_values: Some(vec![
                    "ES256".to_string(),
                    "ES384".to_string(),
                    "ES512".to_string(),
                ]),
            },
        );
        Self {
            vp_formats_supported,
            presentation_definition_supported: Some(true),
            presentation_definition_uri_supported: Some(true),
            client_id_schemes_supported: Some(vec![
                "redirect_uri".to_string(),
                "https".to_string(),
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_wallet_presentation_metadata() {
        let metadata = WalletPresentationMetadata::default();
        // Verify vp_formats_supported contains all expected formats
        assert!(metadata.vp_formats_supported.contains_key("vc+sd-jwt"));
        assert!(metadata.vp_formats_supported.contains_key("mso_mdoc"));
        assert!(metadata.vp_formats_supported.contains_key("jwt_vc_json"));
        // Verify vc+sd-jwt format has correct algorithm fields
        let sd_jwt_format = metadata.vp_formats_supported.get("vc+sd-jwt").unwrap();
        assert_eq!(
            sd_jwt_format.sd_jwt_alg_values,
            Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string()
            ])
        );
        assert_eq!(
            sd_jwt_format.kb_jwt_alg_values,
            Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string()
            ])
        );
        assert!(sd_jwt_format.alg_values.is_none());
        // Verify mso_mdoc format has correct algorithm fields
        let mdoc_format = metadata.vp_formats_supported.get("mso_mdoc").unwrap();
        assert!(mdoc_format.sd_jwt_alg_values.is_none());
        assert!(mdoc_format.kb_jwt_alg_values.is_none());
        assert_eq!(
            mdoc_format.alg_values,
            Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string()
            ])
        );
        // Verify jwt_vc_json format has correct algorithm fields
        let jwt_vc_format = metadata.vp_formats_supported.get("jwt_vc_json").unwrap();
        assert!(jwt_vc_format.sd_jwt_alg_values.is_none());
        assert!(jwt_vc_format.kb_jwt_alg_values.is_none());
        assert_eq!(
            jwt_vc_format.alg_values,
            Some(vec![
                "ES256".to_string(),
                "ES384".to_string(),
                "ES512".to_string()
            ])
        );
        // Verify presentation_definition support
        assert_eq!(metadata.presentation_definition_supported, Some(true));
        assert_eq!(metadata.presentation_definition_uri_supported, Some(true));
        // Verify client_id_schemes_supported
        assert_eq!(
            metadata.client_id_schemes_supported,
            Some(vec!["redirect_uri".to_string(), "https".to_string()])
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
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            },
            "presentation_definition_supported": true,
            "client_id_schemes_supported": ["redirect_uri"],
            "response_modes_supported": ["direct_post"]
        }"#;
        let metadata: WalletPresentationMetadata =
            serde_json::from_str(json).expect("Failed to parse JSON");
        assert!(metadata.vp_formats_supported.contains_key("vc+sd-jwt"));
        assert_eq!(metadata.presentation_definition_supported, Some(true));
        assert_eq!(
            metadata.client_id_schemes_supported,
            Some(vec!["redirect_uri".to_string()])
        );
        assert_eq!(
            metadata.response_modes_supported,
            Some(vec!["direct_post".to_string()])
        );
    }
    #[test]
    fn test_serde_skips_none_fields() {
        let metadata = WalletPresentationMetadata {
            vp_formats_supported: HashMap::new(),
            presentation_definition_supported: None,
            presentation_definition_uri_supported: None,
            client_id_schemes_supported: None,
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
        assert!(!json.contains("client_id_schemes_supported"));
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
}
