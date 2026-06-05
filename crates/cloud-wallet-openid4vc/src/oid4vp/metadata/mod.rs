use std::collections::HashMap;
use std::fmt;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use crate::errors::{Error, ErrorKind};
use crate::utils::validate_non_empty_array_with_kind;

pub mod verifier;
pub mod wallet;

/// Extension format capability object for unknown credential formats.
pub type ExtensionFormatCapability = HashMap<String, Value>;

/// Non-empty JOSE algorithm identifier.
pub type JoseAlgorithmIdentifier = NonEmptyString;

/// Non-empty Data Integrity proof type identifier.
pub type ProofTypeIdentifier = NonEmptyString;

/// Non-empty Data Integrity cryptosuite identifier.
pub type CryptosuiteIdentifier = NonEmptyString;

/// Credential formats supported by a Wallet or Verifier, keyed by Credential Format Identifier.
pub type VpFormatsSupported = HashMap<CredentialFormatIdentifier, VpFormatCapability>;

/// Credential Format Identifier values defined by OpenID4VP Appendix B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CredentialFormatIdentifier {
    /// W3C Verifiable Credentials using JWT.
    JwtVcJson,
    /// W3C Verifiable Credentials using Data Integrity.
    LdpVc,
    /// ISO/IEC 18013-5 mdoc.
    MsoMdoc,
    /// SD-JWT based Verifiable Credentials (I-D.ietf-oauth-sd-jwt-vc).
    DcSdJwt,
    /// Extension format identifier for profiles or future formats.
    Other(String),
}

impl CredentialFormatIdentifier {
    /// Parses a credential format identifier from a string.
    ///
    /// Returns an error if the string is empty or contains only whitespace.
    pub(crate) fn parse(value: String) -> Result<Self, String> {
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

    /// Returns the string representation of this identifier.
    pub(crate) fn as_str(&self) -> &str {
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
    /// Capabilities for `jwt_vc_json` format.
    JwtVcJson(JwtVcJsonFormatCapability),
    /// Capabilities for `ldp_vc` format.
    LdpVc(LdpVcFormatCapability),
    /// Capabilities for `mso_mdoc` format.
    MsoMdoc(MsoMdocFormatCapability),
    /// Capabilities for `dc+sd-jwt` format.
    DcSdJwt(SdJwtVcFormatCapability),
    /// Capabilities for extension formats (unknown to the spec).
    Other(ExtensionFormatCapability),
}

impl VpFormatCapability {
    /// Validates the format capability.
    pub(crate) fn validate(&self) -> Result<(), Error> {
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

/// Metadata for `jwt_vc_json` format.
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtVcJsonFormatCapability {
    /// JOSE algorithms supported for a JWT-secured W3C VC or VP.
    pub alg_values: Option<Vec<JoseAlgorithmIdentifier>>,
}

impl JwtVcJsonFormatCapability {
    /// Validates the JWT VC JSON format capability.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_optional_identifier_array(&self.alg_values, "jwt_vc_json.alg_values")
    }
}

/// Metadata for `ldp_vc` format.
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
    /// Validates the LDP VC format capability.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        validate_optional_identifier_array(&self.proof_type_values, "ldp_vc.proof_type_values")?;
        validate_optional_identifier_array(&self.cryptosuite_values, "ldp_vc.cryptosuite_values")
    }
}

/// Metadata for `mso_mdoc` format.
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
    /// Validates the mso_mdoc format capability.
    pub(crate) fn validate(&self) -> Result<(), Error> {
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

/// Metadata for `dc+sd-jwt` format.
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
    /// Validates the DC SD-JWT VC format capability.
    pub(crate) fn validate(&self) -> Result<(), Error> {
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

    /// Creates a NonEmptyString from a static string without Result wrapping.
    pub fn from_static(value: &'static str) -> Self {
        if value.is_empty() {
            panic!("NonEmptyString cannot be created from empty string");
        }
        Self(value.into())
    }

    /// Returns the string slice.
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
        Self::new(value, "non-empty string identifier").map_err(D::Error::custom)
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
    /// Numeric COSE algorithm identifier (e.g., -7 for ES256).
    Integer(i64),

    /// Fully specified algorithm identifier from a profile or registry.
    String(NonEmptyString),
}

/// Deserializes `vp_formats_supported` from a JSON object.
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

/// Parses a format capability value based on the format identifier.
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

/// Validates an optional array of non-empty string identifiers.
pub(crate) fn validate_optional_identifier_array(
    values: &Option<Vec<NonEmptyString>>,
    field: &str,
) -> Result<(), Error> {
    if let Some(values) = values {
        validate_non_empty_array_with_kind(values, field, ErrorKind::InvalidVerifierMetadata)?;
    }
    Ok(())
}

/// Validates an optional array of COSE algorithm identifiers.
pub(crate) fn validate_optional_cose_array(
    values: &Option<Vec<CoseAlgorithmIdentifier>>,
    field: &str,
) -> Result<(), Error> {
    if let Some(values) = values {
        validate_non_empty_array_with_kind(values, field, ErrorKind::InvalidVerifierMetadata)?;
    }
    Ok(())
}
