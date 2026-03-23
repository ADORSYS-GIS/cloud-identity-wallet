//! Credential format-specific configuration types.
//!
//! These types model the format-specific fields for different credential formats
//! defined in OID4VCI Appendices A.1, A.2, and A.3.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

/// Credential definition for W3C Verifiable Credential formats.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDefinition {
    /// The credential type values.
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// Optional @context array for JSON-LD compatibility.
    #[serde(rename = "@context")]
    pub context: Option<Vec<String>>,

    /// Optional map of claim metadata.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<HashMap<String, Value>>,
}

/// Format-specific configuration for an IETF SD-JWT VC credential.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtVcCredentialConfiguration {
    /// Verifiable Credential Type URI.
    pub vct: String,

    /// Optional credential definition.
    pub credential_definition: Option<CredentialDefinition>,

    /// Optional map of claim metadata.
    pub claims: Option<HashMap<String, Value>>,
}

/// Format-specific configuration for an ISO/IEC 18013-5 mdoc credential.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsoMdocCredentialConfiguration {
    /// Document type string.
    pub doctype: String,

    /// Optional namespace-to-claims map.
    pub claims: Option<HashMap<String, Value>>,
}

/// Format-specific configuration for a W3C Verifiable Credential in JWT JSON format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtVcJsonCredentialConfiguration {
    /// Credential definition.
    pub credential_definition: CredentialDefinition,
}

/// Typed discriminant over all format-specific credential configurations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialFormatDetails {
    /// IETF SD-JWT VC (`"dc+sd-jwt"`).
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt(SdJwtVcCredentialConfiguration),

    /// ISO/IEC 18013-5 mdoc (`"mso_mdoc"`).
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(MsoMdocCredentialConfiguration),

    /// W3C VC in JWT JSON encoding (`"jwt_vc_json"`).
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(JwtVcJsonCredentialConfiguration),

    /// Any format not explicitly modelled above.
    #[serde(untagged)]
    Other {
        /// The format identifier string.
        format: String,
        /// Additional fields.
        #[serde(flatten)]
        extra: serde_json::Value,
    },
}

impl CredentialFormatDetails {
    /// Returns the wire-format string identifier.
    pub fn format_str(&self) -> &str {
        match self {
            Self::DcSdJwt(_) => "dc+sd-jwt",
            Self::MsoMdoc(_) => "mso_mdoc",
            Self::JwtVcJson(_) => "jwt_vc_json",
            Self::Other { format, .. } => format,
        }
    }
}
