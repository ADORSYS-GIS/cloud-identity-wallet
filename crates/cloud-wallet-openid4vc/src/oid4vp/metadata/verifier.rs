//! Verifier Metadata models for OpenID4VP.
//!
//! OpenID4VP Section 11 reuses OAuth Client Metadata from RFC 7591 and adds
//! `vp_formats_supported`.

use std::fmt;

use cloud_wallet_crypto::jwk::{JwkSet, KeyManagement};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};
use crate::impl_string_enum;
use crate::oauth::client_metadata::ClientMetadata;
use crate::utils::validate_non_empty_array_with_kind;

use super::{VpFormatsSupported, deserialize_vp_formats_supported};
/// Verifier Metadata, also known as OAuth Client Metadata in OpenID4VP.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifierMetadata {
    /// RFC 7591 OAuth Client Metadata.
    #[serde(flatten)]
    pub client_metadata: ClientMetadata,

    /// Content encryption algorithms supported for encrypted Authorization Responses.
    pub encrypted_response_enc_values_supported: Option<Vec<JweContentEncryptionAlgorithm>>,

    /// JWE key management algorithms supported for encrypted Authorization Responses.
    ///
    /// The final OpenID4VP text derives the JWE `alg` from the selected JWK,
    /// but this field is accepted for profiles and drafts that advertise it.
    pub encrypted_response_alg_values_supported: Option<Vec<JweKeyManagementAlgorithm>>,

    /// Credential formats the Verifier supports.
    pub vp_formats_supported: VpFormatsSupported,
}

impl VerifierMetadata {
    /// Validates OpenID4VP Verifier Metadata requirements.
    ///
    /// Deserialization already performs this validation. Calling this method is
    /// useful for values constructed or mutated programmatically.
    #[must_use = "validation result must be checked"]
    pub fn validate(&self) -> Result<(), Error> {
        self.client_metadata.validate().map_err(|error| {
            Error::message(
                ErrorKind::InvalidVerifierMetadata,
                format!("client metadata validation failed: {error}"),
            )
        })?;

        if let Some(jwks) = &self.client_metadata.jwks {
            validate_jwks_key_ids(jwks).map_err(|error| {
                Error::message(
                    ErrorKind::InvalidVerifierMetadata,
                    format!("jwks validation failed: {error}"),
                )
            })?;
        }

        if self.vp_formats_supported.is_empty() {
            return invalid("vp_formats_supported must contain at least one entry");
        }

        if let Some(values) = &self.encrypted_response_enc_values_supported {
            validate_non_empty_verifier_array(values, "encrypted_response_enc_values_supported")?;
        }

        if let Some(values) = &self.encrypted_response_alg_values_supported {
            validate_non_empty_verifier_array(values, "encrypted_response_alg_values_supported")?;
            if self.encrypted_response_enc_values_supported.is_none() {
                return invalid(
                    "encrypted_response_enc_values_supported must be present when \
                     encrypted_response_alg_values_supported is present",
                );
            }
        }

        for capability in self.vp_formats_supported.values() {
            capability.validate()?;
        }
        Ok(())
    }
}

fn validate_jwks_key_ids(jwks: &JwkSet) -> Result<(), Error> {
    if jwks.keys.is_empty() {
        return invalid("jwks must contain at least one key");
    }

    for (index, jwk) in jwks.keys.iter().enumerate() {
        if jwk.prm.kid.as_deref().is_none_or(str::is_empty) {
            return invalid(format!(
                "jwks.keys[{index}].kid must be present and non-empty"
            ));
        }
    }
    Ok(())
}

impl<'de> Deserialize<'de> for VerifierMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let metadata: VerifierMetadata =
            VerifierMetadataUnchecked::deserialize(deserializer)?.into();
        metadata.validate().map_err(D::Error::custom)?;
        Ok(metadata)
    }
}

#[skip_serializing_none]
#[derive(Debug, Deserialize)]
struct VerifierMetadataUnchecked {
    #[serde(flatten)]
    client_metadata: ClientMetadata,
    encrypted_response_enc_values_supported: Option<Vec<JweContentEncryptionAlgorithm>>,
    encrypted_response_alg_values_supported: Option<Vec<JweKeyManagementAlgorithm>>,
    #[serde(deserialize_with = "deserialize_vp_formats_supported")]
    vp_formats_supported: VpFormatsSupported,
}

impl From<VerifierMetadataUnchecked> for VerifierMetadata {
    fn from(value: VerifierMetadataUnchecked) -> Self {
        Self {
            client_metadata: value.client_metadata,
            encrypted_response_enc_values_supported: value.encrypted_response_enc_values_supported,
            encrypted_response_alg_values_supported: value.encrypted_response_alg_values_supported,
            vp_formats_supported: value.vp_formats_supported,
        }
    }
}

/// JWE content encryption algorithms from RFC 7518 Section 5.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JweContentEncryptionAlgorithm {
    A128CbcHs256,
    A192CbcHs384,
    A256CbcHs512,
    A128Gcm,
    A192Gcm,
    A256Gcm,
    Other(String),
}

impl_string_enum!(
    JweContentEncryptionAlgorithm,
    {
        A128CbcHs256 => "A128CBC-HS256",
        A192CbcHs384 => "A192CBC-HS384",
        A256CbcHs512 => "A256CBC-HS512",
        A128Gcm => "A128GCM",
        A192Gcm => "A192GCM",
        A256Gcm => "A256GCM"
    },
    "encrypted_response_enc_values_supported"
);

/// JWE key management algorithm identifier used in Verifier metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JweKeyManagementAlgorithm {
    Registered(KeyManagement),
    Other(String),
}

impl JweKeyManagementAlgorithm {
    fn parse(value: String) -> Result<Self, String> {
        if value.trim().is_empty() {
            return Err("encrypted_response_alg_values_supported must not be empty".to_string());
        }

        Ok(match value.as_str() {
            "RSA1_5" => Self::Registered(KeyManagement::Rsa1_5),
            "RSA-OAEP" => Self::Registered(KeyManagement::RsaOaep),
            "RSA-OAEP-256" => Self::Registered(KeyManagement::RsaOaep256),
            "RSA-OAEP-384" => Self::Registered(KeyManagement::RsaOaep384),
            "RSA-OAEP-512" => Self::Registered(KeyManagement::RsaOaep512),
            "A128KW" => Self::Registered(KeyManagement::A128Kw),
            "A192KW" => Self::Registered(KeyManagement::A192Kw),
            "A256KW" => Self::Registered(KeyManagement::A256Kw),
            "dir" => Self::Registered(KeyManagement::Direct),
            "ECDH-ES" => Self::Registered(KeyManagement::EcdhEs),
            "ECDH-ES+A128KW" => Self::Registered(KeyManagement::EcdhEsA128Kw),
            "ECDH-ES+A192KW" => Self::Registered(KeyManagement::EcdhEsA192Kw),
            "ECDH-ES+A256KW" => Self::Registered(KeyManagement::EcdhEsA256Kw),
            "A128GCMKW" => Self::Registered(KeyManagement::A128GcmKw),
            "A192GCMKW" => Self::Registered(KeyManagement::A192GcmKw),
            "A256GCMKW" => Self::Registered(KeyManagement::A256GcmKw),
            "PBES2-HS256+A128KW" => Self::Registered(KeyManagement::Pbes2Hs256A128Kw),
            "PBES2-HS384+A192KW" => Self::Registered(KeyManagement::Pbes2Hs384A192Kw),
            "PBES2-HS512+A256KW" => Self::Registered(KeyManagement::Pbes2Hs512A256Kw),
            _ => Self::Other(value),
        })
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Registered(KeyManagement::Rsa1_5) => "RSA1_5",
            Self::Registered(KeyManagement::RsaOaep) => "RSA-OAEP",
            Self::Registered(KeyManagement::RsaOaep256) => "RSA-OAEP-256",
            Self::Registered(KeyManagement::RsaOaep384) => "RSA-OAEP-384",
            Self::Registered(KeyManagement::RsaOaep512) => "RSA-OAEP-512",
            Self::Registered(KeyManagement::A128Kw) => "A128KW",
            Self::Registered(KeyManagement::A192Kw) => "A192KW",
            Self::Registered(KeyManagement::A256Kw) => "A256KW",
            Self::Registered(KeyManagement::Direct) => "dir",
            Self::Registered(KeyManagement::EcdhEs) => "ECDH-ES",
            Self::Registered(KeyManagement::EcdhEsA128Kw) => "ECDH-ES+A128KW",
            Self::Registered(KeyManagement::EcdhEsA192Kw) => "ECDH-ES+A192KW",
            Self::Registered(KeyManagement::EcdhEsA256Kw) => "ECDH-ES+A256KW",
            Self::Registered(KeyManagement::A128GcmKw) => "A128GCMKW",
            Self::Registered(KeyManagement::A192GcmKw) => "A192GCMKW",
            Self::Registered(KeyManagement::A256GcmKw) => "A256GCMKW",
            Self::Registered(KeyManagement::Pbes2Hs256A128Kw) => "PBES2-HS256+A128KW",
            Self::Registered(KeyManagement::Pbes2Hs384A192Kw) => "PBES2-HS384+A192KW",
            Self::Registered(KeyManagement::Pbes2Hs512A256Kw) => "PBES2-HS512+A256KW",
            Self::Registered(_) => unreachable!("unknown registered JWE key management algorithm"),
            Self::Other(value) => value,
        }
    }
}

impl Serialize for JweKeyManagementAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JweKeyManagementAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

impl fmt::Display for JweKeyManagementAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn validate_non_empty_verifier_array<T>(values: &[T], field: &str) -> Result<(), Error> {
    validate_non_empty_array_with_kind(values, field, ErrorKind::InvalidVerifierMetadata)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::message(
        ErrorKind::InvalidVerifierMetadata,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::client_metadata::{GrantType, ResponseType, TokenEndpointAuthMethod};
    use crate::oid4vp::metadata::{CredentialFormatIdentifier, VpFormatCapability};
    use serde_json::{Value, json};

    fn valid_jwks() -> Value {
        json!({
            "keys": [
                {
                    "kty": "EC",
                    "kid": "enc-key-1",
                    "use": "enc",
                    "alg": "ECDH-ES",
                    "crv": "P-256",
                    "x": "YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
                    "y": "Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"
                }
            ]
        })
    }

    fn minimal_metadata_json() -> Value {
        json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            }
        })
    }

    #[test]
    fn deserializes_valid_verifier_metadata_with_typed_oauth_fields() {
        let metadata: VerifierMetadata = serde_json::from_value(json!({
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code"],
            "response_types": ["vp_token"],
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256"],
                    "kb-jwt_alg_values": ["ES256"]
                }
            }
        }))
        .expect("valid metadata");

        assert_eq!(
            metadata.client_metadata.token_endpoint_auth_method,
            Some(TokenEndpointAuthMethod::ClientSecretBasic)
        );
        assert_eq!(
            metadata.client_metadata.grant_types.as_deref(),
            Some(&[GrantType::AuthorizationCode][..])
        );
        assert_eq!(
            metadata.client_metadata.response_types.as_deref(),
            Some(&[ResponseType::VpToken][..])
        );
        assert!(metadata.validate().is_ok());
    }

    #[test]
    fn supports_rfc7591_and_oid4vp_fields_round_trip() {
        let value = json!({
            "redirect_uris": ["https://client.example.org/cb"],
            "client_name": "Example Verifier",
            "jwks": valid_jwks(),
            "encrypted_response_enc_values_supported": ["A128GCM"],
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256", "ES384"],
                    "kb-jwt_alg_values": ["ES256"]
                },
                "mso_mdoc": {
                    "issuerauth_alg_values": [-9, -50],
                    "deviceauth_alg_values": [-65537, -9]
                }
            },
            "custom_profile_field": {"enabled": true}
        });

        let metadata: VerifierMetadata =
            serde_json::from_value(value.clone()).expect("valid metadata");
        assert_eq!(
            metadata
                .client_metadata
                .additional
                .get("custom_profile_field"),
            Some(&json!({"enabled": true}))
        );
        let round_trip = serde_json::to_value(&metadata).expect("serialize metadata");

        assert_eq!(round_trip, value);
    }

    #[test]
    fn preserves_extension_encrypted_response_alg_values() {
        let mut value = minimal_metadata_json();
        value["encrypted_response_enc_values_supported"] = json!(["A128GCM"]);
        value["encrypted_response_alg_values_supported"] =
            json!(["ECDH-ES", "urn:example:jwe-alg"]);

        let metadata: VerifierMetadata =
            serde_json::from_value(value.clone()).expect("extension alg values are valid");

        assert_eq!(
            metadata.encrypted_response_alg_values_supported.as_deref(),
            Some(
                &[
                    JweKeyManagementAlgorithm::Registered(KeyManagement::EcdhEs),
                    JweKeyManagementAlgorithm::Other("urn:example:jwe-alg".to_string())
                ][..]
            )
        );
        assert_eq!(
            serde_json::to_value(&metadata).expect("serialize metadata"),
            value
        );
    }

    #[test]
    fn rejects_empty_vp_formats_supported() {
        let err = serde_json::from_value::<VerifierMetadata>(json!({
            "vp_formats_supported": {}
        }))
        .unwrap_err();

        assert!(err.to_string().contains("vp_formats_supported"));
    }

    #[test]
    fn rejects_both_jwks_and_jwks_uri() {
        let mut value = minimal_metadata_json();
        value["jwks"] = valid_jwks();
        value["jwks_uri"] = json!("https://client.example.org/jwks.json");

        let err = serde_json::from_value::<VerifierMetadata>(value).unwrap_err();

        assert!(err.to_string().contains("jwks and jwks_uri"));
    }

    #[test]
    fn rejects_inline_jwks_without_kid() {
        let mut value = minimal_metadata_json();
        value["jwks"] = json!({
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
                    "y": "Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"
                }
            ]
        });

        let err = serde_json::from_value::<VerifierMetadata>(value).unwrap_err();

        assert!(err.to_string().contains("kid"));
    }

    #[test]
    fn rejects_encryption_alg_without_enc() {
        let mut value = minimal_metadata_json();
        value["encrypted_response_alg_values_supported"] = json!(["ECDH-ES"]);

        let err = serde_json::from_value::<VerifierMetadata>(value).unwrap_err();

        assert!(
            err.to_string()
                .contains("encrypted_response_enc_values_supported")
        );
    }

    #[test]
    fn rejects_empty_encryption_enc_values() {
        let mut value = minimal_metadata_json();
        value["encrypted_response_enc_values_supported"] = json!([]);

        let err = serde_json::from_value::<VerifierMetadata>(value).unwrap_err();

        assert!(
            err.to_string()
                .contains("encrypted_response_enc_values_supported")
        );
    }

    #[test]
    fn rejects_empty_format_algorithm_arrays() {
        let err = serde_json::from_value::<VerifierMetadata>(json!({
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": []
                }
            }
        }))
        .unwrap_err();

        assert!(err.to_string().contains("sd-jwt_alg_values"));
    }

    #[test]
    fn rejects_fields_that_do_not_belong_to_known_format() {
        let err = serde_json::from_value::<VerifierMetadata>(json!({
            "vp_formats_supported": {
                "mso_mdoc": {
                    "sd-jwt_alg_values": ["ES256"]
                }
            }
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_empty_mdoc_algorithm_arrays() {
        let err = serde_json::from_value::<VerifierMetadata>(json!({
            "vp_formats_supported": {
                "mso_mdoc": {
                    "deviceauth_alg_values": []
                }
            }
        }))
        .unwrap_err();

        assert!(err.to_string().contains("deviceauth_alg_values"));
    }

    #[test]
    fn accepts_empty_mdoc_capability_object() {
        let metadata: VerifierMetadata = serde_json::from_value(json!({
            "vp_formats_supported": {
                "mso_mdoc": {}
            }
        }))
        .expect("valid metadata");

        assert!(matches!(
            metadata.vp_formats_supported[&CredentialFormatIdentifier::MsoMdoc],
            VpFormatCapability::MsoMdoc(_)
        ));
    }
}
