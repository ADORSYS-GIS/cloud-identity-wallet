//! Verifier Metadata models for OpenID4VP.
//!
//! OpenID4VP Section 11 reuses OAuth Client Metadata from RFC 7591 and adds
//! `vp_formats_supported`.

use std::collections::HashMap;
use std::fmt;

use cloud_wallet_crypto::jwk::{JwkSet, KeyManagement};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};
use crate::impl_string_enum;
use crate::oauth::client_metadata::{AdditionalClientMetadata, ClientMetadata};
use crate::utils::{validate_non_empty_array, validate_non_empty_string_array};

/// Extension format capability object.
pub type ExtensionFormatCapability = HashMap<String, Value>;

/// Non-empty JOSE algorithm identifier.
pub type JoseAlgorithmIdentifier = NonEmptyString;

/// Non-empty Data Integrity proof type identifier.
pub type ProofTypeIdentifier = NonEmptyString;

/// Non-empty Data Integrity cryptosuite identifier.
pub type CryptosuiteIdentifier = NonEmptyString;

/// Credential formats supported by a Verifier, keyed by Credential Format Identifier.
pub type VpFormatsSupported = HashMap<CredentialFormatIdentifier, VpFormatCapability>;

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
    pub encrypted_response_alg_values_supported: Option<Vec<KeyManagement>>,

    /// Credential formats the Verifier supports.
    #[serde(serialize_with = "serialize_vp_formats_supported")]
    pub vp_formats_supported: VpFormatsSupported,

    /// Additional client metadata parameters from profiles or deployment-specific extensions.
    #[serde(flatten)]
    pub extra_fields: AdditionalClientMetadata,
}

impl VerifierMetadata {
    /// Validates OpenID4VP Verifier Metadata requirements.
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
            validate_non_empty_array(values, "encrypted_response_enc_values_supported")
                .map_err(to_verifier_error)?;
        }

        if let Some(values) = &self.encrypted_response_alg_values_supported {
            validate_non_empty_array(values, "encrypted_response_alg_values_supported")
                .map_err(to_verifier_error)?;
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
    encrypted_response_alg_values_supported: Option<Vec<KeyManagement>>,
    #[serde(deserialize_with = "deserialize_vp_formats_supported")]
    vp_formats_supported: VpFormatsSupported,
    #[serde(flatten)]
    extra_fields: AdditionalClientMetadata,
}

impl From<VerifierMetadataUnchecked> for VerifierMetadata {
    fn from(value: VerifierMetadataUnchecked) -> Self {
        Self {
            client_metadata: value.client_metadata,
            encrypted_response_enc_values_supported: value.encrypted_response_enc_values_supported,
            encrypted_response_alg_values_supported: value.encrypted_response_alg_values_supported,
            vp_formats_supported: value.vp_formats_supported,
            extra_fields: value.extra_fields,
        }
    }
}

/// Credential Format Identifier values defined by OpenID4VP Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CredentialFormatIdentifier {
    JwtVcJson,
    LdpVc,
    MsoMdoc,
    DcSdJwt,
    Other(String),
}

impl CredentialFormatIdentifier {
    fn parse(value: String) -> Result<Self, String> {
        if value.trim().is_empty() {
            return Err("credential format identifier must not be empty".to_string());
        }

        Ok(match value.as_str() {
            "jwt_vc_json" => Self::JwtVcJson,
            "ldp_vc" => Self::LdpVc,
            "mso_mdoc" => Self::MsoMdoc,
            "dc+sd-jwt" => Self::DcSdJwt,
            _ => Self::Other(value),
        })
    }

    fn as_str(&self) -> &str {
        match self {
            Self::JwtVcJson => "jwt_vc_json",
            Self::LdpVc => "ldp_vc",
            Self::MsoMdoc => "mso_mdoc",
            Self::DcSdJwt => "dc+sd-jwt",
            Self::Other(value) => value,
        }
    }
}

impl Serialize for CredentialFormatIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CredentialFormatIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

impl fmt::Display for CredentialFormatIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Format-specific capability object used in `vp_formats_supported`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpFormatCapability {
    JwtVcJson(JwtVcJsonFormatCapability),
    LdpVc(LdpVcFormatCapability),
    MsoMdoc(MsoMdocFormatCapability),
    DcSdJwt(SdJwtVcFormatCapability),
    Other(ExtensionFormatCapability),
}

impl VpFormatCapability {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::JwtVcJson(capability) => capability.validate(),
            Self::LdpVc(capability) => capability.validate(),
            Self::MsoMdoc(capability) => capability.validate(),
            Self::DcSdJwt(capability) => capability.validate(),
            Self::Other(_) => Ok(()),
        }
    }
}

impl Serialize for VpFormatCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::JwtVcJson(capability) => capability.serialize(serializer),
            Self::LdpVc(capability) => capability.serialize(serializer),
            Self::MsoMdoc(capability) => capability.serialize(serializer),
            Self::DcSdJwt(capability) => capability.serialize(serializer),
            Self::Other(capability) => capability.serialize(serializer),
        }
    }
}

/// Metadata for `jwt_vc_json`.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtVcJsonFormatCapability {
    /// JOSE algorithms supported for a JWT-secured W3C VC or VP.
    pub alg_values: Option<Vec<JoseAlgorithmIdentifier>>,
}

impl JwtVcJsonFormatCapability {
    fn validate(&self) -> Result<(), Error> {
        validate_optional_identifier_array(&self.alg_values, "jwt_vc_json.alg_values")
    }
}

/// Metadata for `ldp_vc`.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdpVcFormatCapability {
    /// Data Integrity proof types supported for a W3C VC or VP.
    pub proof_type_values: Option<Vec<ProofTypeIdentifier>>,

    /// Data Integrity cryptosuites supported for a W3C VC or VP.
    pub cryptosuite_values: Option<Vec<CryptosuiteIdentifier>>,
}

impl LdpVcFormatCapability {
    fn validate(&self) -> Result<(), Error> {
        validate_optional_identifier_array(&self.proof_type_values, "ldp_vc.proof_type_values")?;
        validate_optional_identifier_array(&self.cryptosuite_values, "ldp_vc.cryptosuite_values")
    }
}

/// Metadata for `mso_mdoc`.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsoMdocFormatCapability {
    /// COSE algorithm identifiers supported for mdoc IssuerAuth.
    pub issuerauth_alg_values: Option<Vec<CoseAlgorithmIdentifier>>,

    /// COSE algorithm identifiers supported for mdoc DeviceAuth.
    pub deviceauth_alg_values: Option<Vec<CoseAlgorithmIdentifier>>,
}

impl MsoMdocFormatCapability {
    fn validate(&self) -> Result<(), Error> {
        validate_optional_cose_array(
            &self.issuerauth_alg_values,
            "mso_mdoc.issuerauth_alg_values",
        )?;
        validate_optional_cose_array(
            &self.deviceauth_alg_values,
            "mso_mdoc.deviceauth_alg_values",
        )
    }
}

/// Metadata for `dc+sd-jwt`.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdJwtVcFormatCapability {
    /// JOSE algorithms supported for an Issuer-signed SD-JWT.
    #[serde(rename = "sd-jwt_alg_values")]
    pub sd_jwt_alg_values: Option<Vec<JoseAlgorithmIdentifier>>,

    /// JOSE algorithms supported for a Key Binding JWT.
    #[serde(rename = "kb-jwt_alg_values")]
    pub kb_jwt_alg_values: Option<Vec<JoseAlgorithmIdentifier>>,
}

impl SdJwtVcFormatCapability {
    fn validate(&self) -> Result<(), Error> {
        validate_optional_identifier_array(&self.sd_jwt_alg_values, "dc+sd-jwt.sd-jwt_alg_values")?;
        validate_optional_identifier_array(&self.kb_jwt_alg_values, "dc+sd-jwt.kb-jwt_alg_values")
    }
}

/// Non-empty string identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    pub fn new(value: impl Into<String>, field: &str) -> Result<Self, String> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(format!("{field} must not be empty"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value, "identifier").map_err(D::Error::custom)
    }
}

impl fmt::Display for NonEmptyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// COSE algorithm identifier used by mdoc metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CoseAlgorithmIdentifier {
    /// Numeric COSE algorithm identifier.
    Integer(i64),

    /// Fully specified algorithm identifier from a profile or registry.
    String(NonEmptyString),
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

pub(crate) fn deserialize_vp_formats_supported<'de, D>(
    deserializer: D,
) -> Result<VpFormatsSupported, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = HashMap::<String, Value>::deserialize(deserializer)?;
    let mut formats = HashMap::with_capacity(raw.len());

    for (format, value) in raw {
        let format = CredentialFormatIdentifier::parse(format).map_err(D::Error::custom)?;
        let capability = parse_format_capability(&format, value).map_err(D::Error::custom)?;
        formats.insert(format, capability);
    }
    Ok(formats)
}

pub(crate) fn serialize_vp_formats_supported<S>(
    formats: &VpFormatsSupported,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    formats.serialize(serializer)
}

fn parse_format_capability(
    format: &CredentialFormatIdentifier,
    value: Value,
) -> Result<VpFormatCapability, serde_json::Error> {
    Ok(match format {
        CredentialFormatIdentifier::JwtVcJson => {
            VpFormatCapability::JwtVcJson(serde_json::from_value(value)?)
        }
        CredentialFormatIdentifier::LdpVc => {
            VpFormatCapability::LdpVc(serde_json::from_value(value)?)
        }
        CredentialFormatIdentifier::MsoMdoc => {
            VpFormatCapability::MsoMdoc(serde_json::from_value(value)?)
        }
        CredentialFormatIdentifier::DcSdJwt => {
            VpFormatCapability::DcSdJwt(serde_json::from_value(value)?)
        }
        CredentialFormatIdentifier::Other(_) => {
            VpFormatCapability::Other(serde_json::from_value(value)?)
        }
    })
}

fn validate_optional_identifier_array(
    values: &Option<Vec<NonEmptyString>>,
    field: &str,
) -> Result<(), Error> {
    if let Some(values) = values {
        let string_values: Vec<String> = values.iter().map(ToString::to_string).collect();
        validate_non_empty_string_array(&string_values, field).map_err(to_verifier_error)?;
    }
    Ok(())
}

fn validate_optional_cose_array(
    values: &Option<Vec<CoseAlgorithmIdentifier>>,
    field: &str,
) -> Result<(), Error> {
    if let Some(values) = values {
        validate_non_empty_array(values, field).map_err(to_verifier_error)?;
    }
    Ok(())
}

fn to_verifier_error(error: Error) -> Error {
    Error::message(ErrorKind::InvalidVerifierMetadata, error.to_string())
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
    use serde_json::json;

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
        let round_trip = serde_json::to_value(&metadata).expect("serialize metadata");

        assert_eq!(round_trip, value);
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
