//! Credential configuration types per [OpenID4VCI §12.2.3].
//!
//! [OpenID4VCI §12.2.3]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.3

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::claim_path_pointer::ClaimPathPointer;
use super::credential_formats::CredentialFormatDetails;
use super::css_color::CssColor;
use super::signing_algorithm::SigningAlgorithm;

/// Key attestation requirements for proof types.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    /// Required key storage security levels.
    pub key_storage: Option<Vec<String>>,

    /// Required user authentication security levels.
    pub user_authentication: Option<Vec<String>>,
}

/// Metadata for a single proof type.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Non-empty list of signing algorithm identifiers the issuer accepts.
    pub proof_signing_alg_values_supported: Vec<SigningAlgorithm>,
    pub key_attestations_required: Option<KeyAttestationsRequired>,
}

/// One entry in the `credential_configurations_supported` map.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Optional identifier for this credential configuration (non-spec, used by some implementations).
    pub id: Option<String>,

    /// Typed format details.
    #[serde(flatten)]
    pub format_details: CredentialFormatDetails,
    /// OAuth 2.0 scope value used to request this credential type.
    pub scope: Option<String>,

    /// Cryptographic key binding methods supported.
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    /// Algorithm identifiers for JWT-based formats SHOULD be JWS names from [IANA JOSE Registry].
    ///
    /// [IANA JOSE Registry]: https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
    pub credential_signing_alg_values_supported: Option<Vec<SigningAlgorithm>>,
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Credential metadata for display and claims.
    pub credential_metadata: Option<CredentialMetadata>,
}

/// Credential metadata for display and claims.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Per-language display metadata.
    pub display: Option<Vec<CredentialDisplay>>,

    /// Claims description objects.
    pub claims: Option<Vec<ClaimDescription>>,
}

/// Per-language display properties for a credential.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /// Human-readable name of the credential type.
    pub name: String,

    /// BCP47 language tag.
    pub locale: Option<String>,

    /// Optional logo for the credential.
    pub logo: Option<Logo>,
    pub background_color: Option<CssColor>,
    pub background_image: Option<BackgroundImage>,
    pub text_color: Option<CssColor>,
    pub description: Option<String>,
}

/// Logo information for display objects.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Logo {
    /// URI where the wallet can obtain the logo image.
    pub uri: url::Url,
    /// Alternative text for accessibility.
    pub alt_text: Option<String>,
}

/// Background image for credential display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackgroundImage {
    /// URI where the wallet can obtain the background image.
    pub uri: url::Url,
}

/// Description of a claim in issued credentials per [Appendix B.2].
///
/// [Appendix B.2]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-b.2
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimDescription {
    /// Claims path pointer per [Appendix C].
    ///
    /// [Appendix C]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-C
    pub path: ClaimPathPointer,
    /// Boolean indicating if the claim is always included. Defaults to false when omitted.
    #[serde(default)]
    pub mandatory: bool,

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
