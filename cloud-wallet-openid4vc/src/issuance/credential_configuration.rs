//! Credential configuration and metadata types.
//!
//! These types model the credential configuration entries in the
//! `credential_configurations_supported` map of the issuer metadata.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use super::credential_formats::CredentialFormatDetails;

/// Key attestation requirements for proof types.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    /// Required key storage security levels.
    pub key_storage: Option<Vec<String>>,

    /// Required user authentication security levels.
    pub user_authentication: Option<Vec<String>>,
}

/// Metadata for a single proof type supported by a credential configuration.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Non-empty list of signing algorithm identifiers that the issuer accepts.
    pub proof_signing_alg_values_supported: Vec<String>,

    /// Key attestation requirements for high-assurance issuance flows.
    pub key_attestations_required: Option<KeyAttestationsRequired>,
}

/// One entry in the `credential_configurations_supported` map.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Typed format details.
    #[serde(flatten)]
    pub format_details: CredentialFormatDetails,

    /// Unique identifier for this credential configuration.
    ///
    /// Not part of OID4VCI spec; included for backward compatibility with Keycloak.
    pub id: Option<String>,

    /// OAuth 2.0 scope value used to request this credential type.
    pub scope: Option<String>,

    /// Cryptographic key binding methods supported.
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Signing algorithms used by the issuer.
    pub credential_signing_alg_values_supported: Option<Vec<Value>>,

    /// Supported key proof types.
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Credential metadata for display and claims.
    pub credential_metadata: Option<CredentialMetadata>,
}

/// Credential metadata for usage and display of issued credentials.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Per-language display metadata.
    pub display: Option<Vec<CredentialDisplay>>,

    /// Claims description objects.
    pub claims: Option<Vec<ClaimDescription>>,
}

/// Per-language display properties for a credential configuration.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /// Human-readable name of the credential type.
    pub name: String,

    /// BCP47 language tag.
    pub locale: Option<String>,

    /// Optional logo for the credential.
    pub logo: Option<Logo>,

    /// Optional background color (CSS color value).
    pub background_color: Option<String>,

    /// Optional background image.
    pub background_image: Option<BackgroundImage>,

    /// Optional text color (CSS color value).
    pub text_color: Option<String>,

    /// Optional description for the credential type.
    pub description: Option<String>,
}

/// Logo information for display objects.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Logo {
    /// URI where the wallet can obtain the logo image.
    pub uri: url::Url,

    /// Alternative text for the logo image, used for accessibility.
    pub alt_text: Option<String>,
}

/// Background image for credential display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackgroundImage {
    /// URI where the wallet can obtain the background image.
    pub uri: url::Url,
}

/// Description of a claim in issued credentials (Appendix B.2).
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimDescription {
    /// Path to the claim within the credential.
    pub path: Vec<String>,

    /// Whether the claim is always included.
    pub mandatory: Option<bool>,

    /// Per-language display properties for this claim.
    pub display: Option<Vec<ClaimDisplay>>,
}

/// Display properties for a claim.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimDisplay {
    /// Display name for the claim.
    pub name: Option<String>,

    /// BCP47 language tag.
    pub locale: Option<String>,
}
