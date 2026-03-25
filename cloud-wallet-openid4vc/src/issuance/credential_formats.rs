//! Credential format-specific configuration types.
//
//! These types model the format-specific fields for different credential formats
//! defined in:
//! - [Appendix A.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.1): W3C Verifiable Credentials
//! - [Appendix A.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.2): Mobile Documents (mdoc)
//! - [Appendix A.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.3): IETF SD-JWT VC

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

/// Credential definition for W3C Verifiable Credential formats.
///
/// As defined in [Appendix A.1.1.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.1.1.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDefinition {
    /// The credential type values (REQUIRED).
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// Optional @context array for JSON-LD compatibility.
    /// REQUIRED for `ldp_vc` and `jwt_vc_json-ld` formats.
    #[serde(rename = "@context")]
    pub context: Option<Vec<String>>,
}

/// Format-specific configuration for an IETF SD-JWT VC credential.
///
/// As defined in [Appendix A.3.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.3.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtVcCredentialConfiguration {
    /// Verifiable Credential Type URI (REQUIRED).
    pub vct: String,

    /// Optional credential definition (non-spec, used by some implementations like Keycloak).
    pub credential_definition: Option<CredentialDefinition>,
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

/// Format-specific configuration for a W3C Verifiable Credential in JWT format (not using JSON-LD).
///
/// As defined in [Appendix A.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.1.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtVcJsonCredentialConfiguration {
    /// Credential definition (REQUIRED).
    pub credential_definition: CredentialDefinition,
}

/// Format-specific configuration for a W3C Verifiable Credential secured using
/// Data Integrity with JSON-LD and Linked Data canonicalization.
///
/// As defined in [Appendix A.1.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.1.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LdpVcCredentialConfiguration {
    /// Credential definition (REQUIRED, must include @context).
    pub credential_definition: CredentialDefinition,
}

/// Format-specific configuration for a W3C Verifiable Credential signed as JWT using JSON-LD.
///
/// As defined in [Appendix A.1.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-a.1.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtVcJsonLdCredentialConfiguration {
    /// Credential definition (REQUIRED, must include @context).
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

    /// W3C VC in JWT format, not using JSON-LD (`"jwt_vc_json"`).
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(JwtVcJsonCredentialConfiguration),

    /// W3C VC secured using Data Integrity with JSON-LD (`"ldp_vc"`).
    #[serde(rename = "ldp_vc")]
    LdpVc(LdpVcCredentialConfiguration),

    /// W3C VC signed as JWT using JSON-LD (`"jwt_vc_json-ld"`).
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd(JwtVcJsonLdCredentialConfiguration),

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
            Self::LdpVc(_) => "ldp_vc",
            Self::JwtVcJsonLd(_) => "jwt_vc_json-ld",
            Self::Other { format, .. } => format,
        }
    }
}
