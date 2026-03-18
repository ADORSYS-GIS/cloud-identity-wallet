//! Data models for the OpenID for Verifiable Credential Issuance (OID4VCI) 1.0
//! **Credential Issuer Metadata** document (§12.2).
//!
//! The metadata is served by a Credential Issuer at the well-known path:
//!
//! ```text
//! GET /.well-known/openid-credential-issuer HTTP/1.1
//! Host: issuer.example.com
//! ```
//!
//! and describes the issuer's technical capabilities, supported credential
//! formats, and optional display information.
//!
//! # Credential Formats
//!
//! Format-specific configuration is represented by the [`CredentialFormatDetails`]
//! enum, which provides a typed variant for each format defined in the
//! specification's Appendix A:
//!
//! | Variant | JSON `format` value | Spec |
//! |---------|---------------------|------|
//! | [`CredentialFormatDetails::DcSdJwt`] | `"dc+sd-jwt"` | Appendix A.3 |
//! | [`CredentialFormatDetails::MsoMdoc`] | `"mso_mdoc"` | Appendix A.2 |
//! | [`CredentialFormatDetails::JwtVcJson`] | `"jwt_vc_json"` | Appendix A.1 |
//! | [`CredentialFormatDetails::Other`] | any other string | — |
//!
//! # Reference
//!
//! <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata>

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::errors::{Error, ErrorKind};

// ─────────────────────────────────────────────────────────────────────────────
// Display helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Logo information for display objects.
///
/// Defined in OID4VCI §12.2.4 inside the `display` array of
/// [`CredentialIssuerMetadata`] and [`CredentialDisplay`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Logo {
    /// URI where the wallet can obtain the logo image.
    ///
    /// The scheme is not restricted; `https:` and `data:` URIs are both valid.
    pub uri: String,

    /// Alternative text for the logo image, used for accessibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// Per-language display properties for the Credential Issuer itself.
///
/// One object exists per supported language. The `locale` field identifies the
/// language using a BCP47 language tag (e.g. `"en-US"`, `"de"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuerDisplay {
    /// Human-readable display name of the Credential Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// BCP47 language tag (e.g. `"en-US"`) identifying the language of this
    /// display object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Optional logo for the Credential Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
}

/// Per-language display properties for a single credential configuration.
///
/// Carries the credential's name, description, background, text colors and an
/// optional logo, each scoped to one locale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /// Human-readable name of the credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// BCP47 language tag identifying the language of this display object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Optional logo for the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,

    /// Optional background color expressed as a CSS color value (e.g. `"#12107c"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Optional text color expressed as a CSS color value (e.g. `"#FFFFFF"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,

    /// Optional description for the credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof types
// ─────────────────────────────────────────────────────────────────────────────

/// Key attestation requirements for proof types.
///
/// Used in high-assurance credential issuance flows to specify required
/// security levels for key storage and user authentication.
///
/// Defined in OID4VCI §12.2.4 inside `proof_types_supported`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    /// Required key storage security levels (e.g. `"iso_18045_moderate"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<Vec<String>>,

    /// Required user authentication security levels (e.g. `"iso_18045_moderate"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<Vec<String>>,
}

/// Metadata for a single proof type supported by a credential configuration.
///
/// Lives under `proof_types_supported` in a [`CredentialConfiguration`]. The
/// map key (e.g. `"jwt"`, `"cwt"`) names the proof type; this struct is the
/// corresponding value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Non-empty list of signing algorithm identifiers (JWA / CASE) that the
    /// issuer accepts for this proof type.
    pub proof_signing_alg_values_supported: Vec<String>,

    /// Key attestation requirements for high-assurance issuance flows.
    ///
    /// When present, specifies required security levels for key storage
    /// and/or user authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_attestations_required: Option<KeyAttestationsRequired>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Format-specific credential configuration models (OID4VCI Appendix A)
// ─────────────────────────────────────────────────────────────────────────────

/// Credential definition for W3C Verifiable Credential formats.
///
/// Required inside [`JwtVcJsonCredentialConfiguration`] (Appendix A.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDefinition {
    /// The credential type values (e.g. `["VerifiableCredential", "UniversityDegreeCredential"]`).
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// Optional map of claim metadata; the keys are claim names.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<HashMap<String, Value>>,
}

/// Nested credential metadata for SD-JWT VC configurations.
///
/// The spec's Appendix I example shows SD-JWT VC configurations with a nested
/// `credential_metadata` object containing `display` and `claims` arrays.
/// This structure supports that format-specific nesting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtVcCredentialMetadata {
    /// Per-language display metadata for this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// Optional array of claim metadata objects.
    ///
    /// Each claim object contains `path`, `display`, `mandatory`, and
    /// optionally `value_type` fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<Value>>,
}

/// Format-specific configuration for an **IETF SD-JWT VC** credential
/// (`"dc+sd-jwt"`, OID4VCI Appendix A.3).
///
/// The `vct` claim is the Verifiable Credential Type and uniquely identifies
/// the credential schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SdJwtVcCredentialConfiguration {
    /// Verifiable Credential Type URI — **REQUIRED** for SD-JWT VC.
    ///
    /// Corresponds to the `vct` header claim in the issued SD-JWT.
    pub vct: String,

    /// Optional map of claim metadata for selective disclosure.
    ///
    /// This is the format-agnostic location. For SD-JWT VC-specific
    /// nesting, use `credential_metadata` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, Value>>,

    /// Nested credential metadata following SD-JWT VC spec structure.
    ///
    /// When present, contains `display` and `claims` in the format shown
    /// in Appendix I of the OID4VCI specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<SdJwtVcCredentialMetadata>,
}

/// Format-specific configuration for an **ISO/IEC 18013-5 mdoc** credential
/// (`"mso_mdoc"`, OID4VCI Appendix A.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MsoMdocCredentialConfiguration {
    /// Document type string — **REQUIRED** for ISO mdoc.
    ///
    /// Identifies the type of the mobile document (e.g. `"org.iso.18013.5.1.mDL"`).
    pub doctype: String,

    /// Optional namespace-to-claims map for this document type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, Value>>,
}

/// Format-specific configuration for a **W3C Verifiable Credential in JWT JSON** format
/// (`"jwt_vc_json"`, OID4VCI Appendix A.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtVcJsonCredentialConfiguration {
    /// Credential definition including the `type` array — **REQUIRED**.
    pub credential_definition: CredentialDefinition,
}

/// Typed discriminant over all format-specific credential configurations.
///
/// The `format` key in the JSON object determines which variant is used. Use
/// pattern matching to access format-specific required fields:
///
/// ```
/// use cloud_wallet_openid4vc::issuer_metadata::{CredentialFormatDetails, CredentialConfiguration};
///
/// # let json = serde_json::json!({
/// #     "format": "dc+sd-jwt",
/// #     "vct": "https://credentials.example.com/identity"
/// # });
/// let config: CredentialConfiguration = serde_json::from_value(json).unwrap();
/// if let CredentialFormatDetails::DcSdJwt(sd) = &config.format_details {
///     println!("vct = {}", sd.vct);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialFormatDetails {
    /// IETF SD-JWT VC (`"dc+sd-jwt"`) — requires `vct`.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt(SdJwtVcCredentialConfiguration),

    /// ISO/IEC 18013-5 mdoc (`"mso_mdoc"`) — requires `doctype`.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(MsoMdocCredentialConfiguration),

    /// W3C VC in JWT JSON encoding (`"jwt_vc_json"`) — requires `credential_definition`.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(JwtVcJsonCredentialConfiguration),

    /// Any format not explicitly modelled above.
    ///
    /// The raw format string is preserved in the `format` field and any
    /// additional fields are collected in `extra`. This enables wallets to
    /// process configurations for formats they don't understand, as required
    /// by §12.2.4 of the specification.
    #[serde(untagged)]
    Other {
        /// The format identifier string (e.g., "some_future_format").
        format: String,
        /// Additional fields that are not recognized by this implementation.
        #[serde(flatten)]
        extra: serde_json::Value,
    },
}

impl CredentialFormatDetails {
    /// Returns the wire-format string identifier (e.g. `"dc+sd-jwt"`).
    pub fn format_str(&self) -> &str {
        match self {
            Self::DcSdJwt(_) => "dc+sd-jwt",
            Self::MsoMdoc(_) => "mso_mdoc",
            Self::JwtVcJson(_) => "jwt_vc_json",
            Self::Other { format, .. } => format,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Credential configuration
// ─────────────────────────────────────────────────────────────────────────────

/// One entry in the `credential_configurations_supported` map.
///
/// Describes a specific credential that the issuer can issue. Common fields
/// (scope, proof types, display) are in this struct. Format-specific required
/// fields are in the `format_details` field as a typed
/// [`CredentialFormatDetails`] variant — no raw `HashMap` is needed.
///
/// # Deserialisation
///
/// The JSON object's `format` key drives which [`CredentialFormatDetails`]
/// variant is used. All fields of the format-specific struct are expected at
/// the top level of the same JSON object (internally-tagged flat envelope).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Typed format details, including the `format` discriminant and all
    /// format-mandatory fields.
    #[serde(flatten)]
    pub format_details: CredentialFormatDetails,

    /// OAuth 2.0 scope value used to request this credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Cryptographic key binding methods supported by the issuer for this
    /// credential (e.g. `["jwk"]`, `["case_key"]`, `["did:example"]`).
    ///
    /// When present, `proof_types_supported` **MUST** also be present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Signing algorithms used by the issuer to sign issued credentials.
    ///
    /// Per §12.2.4, algorithm identifier types and values are determined by the
    /// Credential Format and defined in Appendix A:
    /// - JWT-based formats (jwt_vc_json, dc+sd-jwt): string identifiers from
    ///   the JWA registry (e.g., `"ES256"`, `"RS256"`)
    /// - COSE-based formats (mso_mdoc): integer identifiers from the CASE
    ///   Algorithms IANA registry (e.g., `-7` for ES256, `-257` for RS256)
    ///
    /// Validation of these values is format-specific and handled elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<Value>>,

    /// Supported key proof types, keyed by proof type name (e.g. `"jwt"`).
    ///
    /// **MUST** be present when `cryptographic_binding_methods_supported` is
    /// present; **MUST** be omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Per-language display metadata for this credential configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption objects
// ─────────────────────────────────────────────────────────────────────────────

/// Encryption capability descriptor, used for both request and response
/// encryption (`credential_request_encryption` and
/// `credential_response_encryption` fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialEncryptionInfo {
    /// JSON Web Key Set containing public keys for the key agreement used in
    /// encryption.
    ///
    /// Required for request encryption, optional for response encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,

    /// JWE `alg` algorithm values supported (for response encryption only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values_supported: Option<Vec<String>>,

    /// JWE `enc` content-encryption algorithm values supported.
    pub enc_values_supported: Vec<String>,

    /// JWE `zip` compression algorithm values supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_values_supported: Option<Vec<String>>,

    /// Whether encryption is required on top of TLS.
    pub encryption_required: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch issuance
// ─────────────────────────────────────────────────────────────────────────────

/// Information about the issuer's support for batch credential issuance.
///
/// Presence of this object signals that the issuer supports more than one
/// key proof in the `proofs` array of a Credential Request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchCredentialIssuance {
    /// Maximum size of the `proofs` array in a Credential Request.
    ///
    /// **MUST** be 2 or greater.
    pub batch_size: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level metadata document
// ─────────────────────────────────────────────────────────────────────────────

/// The Credential Issuer Metadata document (OID4VCI §12.2).
///
/// Served at `/.well-known/openid-credential-issuer` (or with the issuer's
/// path component appended, as described in §12.2.2).
///
/// After deserializing, call [`CredentialIssuerMetadata::validate`] to enforce
/// specification constraints that cannot be expressed in the type system alone
/// (e.g. HTTPS-only URLs, non-empty configuration map).
///
/// # Example
///
/// ```
/// use cloud_wallet_openid4vc::issuer_metadata::{
///     CredentialIssuerMetadata, CredentialFormatDetails,
/// };
///
/// let json = serde_json::json!({
///     "credential_issuer": "https://issuer.example.com",
///     "credential_endpoint": "https://issuer.example.com/credential",
///     "credential_configurations_supported": {
///         "ExampleCredential": {
///             "format": "dc+sd-jwt",
///             "vct": "https://credentials.example.com/identity"
///         }
///     }
/// });
///
/// let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
/// metadata.validate().unwrap();
///
/// let config = metadata.credential_configurations_supported.get("ExampleCredential").unwrap();
/// assert!(matches!(config.format_details, CredentialFormatDetails::DcSdJwt(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// Unique URL identifier of the Credential Issuer (HTTPS, no query/fragment).
    ///
    /// **REQUIRED.** The value MUST match the URL from which the metadata was
    /// retrieved (§12.2.1).
    pub credential_issuer: String,

    /// OAuth 2.0 Authorization Server identifiers relied on by this issuer.
    ///
    /// If absent, the issuer itself acts as the Authorization Server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// URL of the Credential Endpoint (§8.2, REQUIRED, HTTPS).
    pub credential_endpoint: String,

    /// URL of the Nonce Endpoint, if supported (§7, HTTPS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,

    /// URL of the Deferred Credential Endpoint, if supported (§9, HTTPS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// URL of the Notification Endpoint, if supported (§11, HTTPS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,

    /// URL of the Batch Credential Endpoint, if supported (HTTPS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_endpoint: Option<String>,

    /// Information about request-level encryption support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<CredentialEncryptionInfo>,

    /// Information about response-level encryption support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialEncryptionInfo>,

    /// Batch issuance capability; presence implies support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// Per-language display information for the Credential Issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<IssuerDisplay>>,

    /// Map of supported credential configurations, keyed by a unique config ID.
    ///
    /// **REQUIRED.** Must contain at least one entry. The keys are used in
    /// Credential Offers to reference specific credential types.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
}

impl CredentialIssuerMetadata {
    /// Validates structural invariants required by the OID4VCI specification.
    ///
    /// Checks performed:
    /// 1. `credential_endpoint` uses the `https` scheme.
    /// 2. All optional endpoint URLs use the `https` scheme when present.
    /// 3. `credential_configurations_supported` is non-empty.
    /// 4. For each configuration: if `cryptographic_binding_methods_supported`
    ///    is set, `proof_types_supported` must also be set (§12.2.4).
    /// 5. `credential_issuer` uses the `https` scheme unconditionally (§12.2.1).
    /// 6. Each `authorization_servers` entry uses the `https` scheme when present.
    /// 7. `batch_credential_issuance.batch_size` is >= 2 when present (§12.2.4).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidIssuerMetadata`] if any constraint is
    /// violated.
    pub fn validate(&self) -> Result<(), Error> {
        // 1. credential_endpoint must use HTTPS.
        require_https(&self.credential_endpoint, "credential_endpoint")?;

        // 2. Optional endpoint URLs must use HTTPS when present.
        for (field, url) in [
            ("nonce_endpoint", self.nonce_endpoint.as_deref()),
            (
                "deferred_credential_endpoint",
                self.deferred_credential_endpoint.as_deref(),
            ),
            (
                "notification_endpoint",
                self.notification_endpoint.as_deref(),
            ),
            (
                "batch_credential_endpoint",
                self.batch_credential_endpoint.as_deref(),
            ),
        ] {
            if let Some(url) = url {
                require_https(url, field)?;
            }
        }

        // 3. credential_configurations_supported must not be empty.
        if self.credential_configurations_supported.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidIssuerMetadata,
                "credential_configurations_supported must contain at least one entry",
            ));
        }

        // 4. Per-configuration invariants.
        for (id, config) in &self.credential_configurations_supported {
            if config.cryptographic_binding_methods_supported.is_some()
                && config.proof_types_supported.is_none()
            {
                return Err(Error::message(
                    ErrorKind::InvalidIssuerMetadata,
                    format!(
                        "credential configuration \"{id}\": proof_types_supported must be \
                         present when cryptographic_binding_methods_supported is set"
                    ),
                ));
            }
        }

        // 5. credential_issuer MUST use HTTPS unconditionally (§12.2.1).
        require_https(&self.credential_issuer, "credential_issuer")?;

        // 6. authorization_servers validation (§12.2.4).
        // When present, each authorization server URL must use HTTPS.
        if let Some(auth_servers) = &self.authorization_servers {
            for auth_server in auth_servers {
                require_https(auth_server, "authorization_servers entry")?;
            }
        }

        // 7. batch_credential_issuance.batch_size MUST be >= 2 (§12.2.4).
        if let Some(batch) = &self.batch_credential_issuance {
            if batch.batch_size < 2 {
                return Err(Error::message(
                    ErrorKind::InvalidIssuerMetadata,
                    format!(
                        "batch_credential_issuance.batch_size must be >= 2, got {}",
                        batch.batch_size
                    ),
                ));
            }
        }

        Ok(())
    }
}

/// Returns an error if `raw_url` cannot be parsed or does not use the `https`
/// scheme.
fn require_https(raw_url: &str, field: &str) -> Result<(), Error> {
    let url = Url::parse(raw_url).map_err(|e| {
        Error::message(
            ErrorKind::InvalidIssuerMetadata,
            format!("field \"{field}\" is not a valid URL: {e}"),
        )
    })?;
    if url.scheme() != "https" {
        return Err(Error::message(
            ErrorKind::InvalidIssuerMetadata,
            format!(
                "field \"{field}\" must use the https scheme, got \"{}\"",
                url.scheme()
            ),
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Minimal valid metadata — one SD-JWT VC config (only required fields).
    fn minimal_json() -> serde_json::Value {
        json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://credentials.example.com/identity"
                }
            }
        })
    }

    // ── Format model deserialization ──────────────────────────────────────────

    #[test]
    fn sd_jwt_vc_format_deserializes_to_typed_variant() {
        let json = json!({
            "format": "dc+sd-jwt",
            "vct": "https://credentials.example.com/identity"
        });
        let config: CredentialConfiguration = serde_json::from_value(json).unwrap();
        match &config.format_details {
            CredentialFormatDetails::DcSdJwt(sd) => {
                assert_eq!(sd.vct, "https://credentials.example.com/identity");
            }
            other => panic!("expected DcSdJwt, got {other:?}"),
        }
    }

    #[test]
    fn mso_mdoc_format_deserializes_to_typed_variant() {
        let json = json!({
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL"
        });
        let config: CredentialConfiguration = serde_json::from_value(json).unwrap();
        match &config.format_details {
            CredentialFormatDetails::MsoMdoc(mdoc) => {
                assert_eq!(mdoc.doctype, "org.iso.18013.5.1.mDL");
            }
            other => panic!("expected MsoMdoc, got {other:?}"),
        }
    }

    #[test]
    fn jwt_vc_json_format_deserializes_to_typed_variant() {
        let json = json!({
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": ["VerifiableCredential", "UniversityDegreeCredential"]
            }
        });
        let config: CredentialConfiguration = serde_json::from_value(json).unwrap();
        match &config.format_details {
            CredentialFormatDetails::JwtVcJson(jwt) => {
                assert!(
                    jwt.credential_definition
                        .types
                        .contains(&"UniversityDegreeCredential".to_string())
                );
            }
            other => panic!("expected JwtVcJson, got {other:?}"),
        }
    }

    #[test]
    fn unknown_format_deserializes_to_other_variant() {
        let json = json!({
            "format": "some_future_format",
            "custom_field": "custom_value"
        });
        let config: CredentialConfiguration = serde_json::from_value(json).unwrap();
        match &config.format_details {
            CredentialFormatDetails::Other { format, extra } => {
                assert_eq!(format, "some_future_format");
                assert_eq!(extra["custom_field"], "custom_value");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn format_str_helper_returns_correct_strings() {
        let sd = CredentialFormatDetails::DcSdJwt(SdJwtVcCredentialConfiguration {
            vct: "https://example.com/vct".to_string(),
            claims: None,
            credential_metadata: None,
        });
        assert_eq!(sd.format_str(), "dc+sd-jwt");

        let mdoc = CredentialFormatDetails::MsoMdoc(MsoMdocCredentialConfiguration {
            doctype: "org.iso.18013.5.1.mDL".to_string(),
            claims: None,
        });
        assert_eq!(mdoc.format_str(), "mso_mdoc");

        let jwt = CredentialFormatDetails::JwtVcJson(JwtVcJsonCredentialConfiguration {
            credential_definition: CredentialDefinition {
                types: vec!["VerifiableCredential".to_string()],
                credential_subject: None,
            },
        });
        assert_eq!(jwt.format_str(), "jwt_vc_json");

        let other = CredentialFormatDetails::Other {
            format: "custom_format".to_string(),
            extra: serde_json::Value::Null,
        };
        assert_eq!(other.format_str(), "custom_format");
    }

    // ── Construction / round-trip ─────────────────────────────────────────────

    #[test]
    fn valid_minimal_metadata_round_trips() {
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(minimal_json()).expect("deserialize minimal metadata");
        metadata.validate().expect("validate minimal metadata");
        assert_eq!(metadata.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            metadata.credential_endpoint,
            "https://issuer.example.com/credential"
        );
        assert!(metadata.authorization_servers.is_none());
        assert!(metadata.display.is_none());
    }

    #[test]
    fn serialization_round_trip() {
        let original: CredentialIssuerMetadata =
            serde_json::from_value(minimal_json()).expect("deserialize");
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: CredentialIssuerMetadata =
            serde_json::from_str(&serialized).expect("deserialize round-trip");
        assert_eq!(original, deserialized);
    }

    // ── Full SD-JWT VC example (spec Appendix I.1) ────────────────────────────

    #[test]
    fn full_sd_jwt_vc_example_parses() {
        let json = json!({
            "credential_issuer": "https://credential-issuer.example.com",
            "authorization_servers": ["https://server.example.com"],
            "credential_endpoint": "https://credential-issuer.example.com/credential",
            "nonce_endpoint": "https://credential-issuer.example.com/nonce",
            "deferred_credential_endpoint": "https://credential-issuer.example.com/deferred",
            "notification_endpoint": "https://credential-issuer.example.com/notification",
            "display": [
                {
                    "name": "Example University",
                    "locale": "en-US",
                    "logo": {
                        "uri": "https://university.example.edu/public/logo.png",
                        "alt_text": "a square logo of a university"
                    }
                }
            ],
            "credential_configurations_supported": {
                "UniversityDegreeCredential": {
                    "format": "dc+sd-jwt",
                    "scope": "UniversityDegree",
                    "vct": "https://credentials.example.com/identity/UniversityDegree",
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256"]
                        }
                    },
                    "display": [
                        {
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "uri": "https://university.example.edu/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                }
            }
        });

        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("parse SD-JWT VC example");
        metadata.validate().expect("validate SD-JWT VC example");

        // Issuer display
        let display = metadata.display.as_ref().unwrap();
        assert_eq!(display.len(), 1);
        assert_eq!(display[0].name.as_deref(), Some("Example University"));
        assert_eq!(display[0].locale.as_deref(), Some("en-US"));

        // Authorization servers
        let auth_servers = metadata.authorization_servers.as_ref().unwrap();
        assert_eq!(auth_servers[0], "https://server.example.com");

        // Credential configuration — typed format
        let config = metadata
            .credential_configurations_supported
            .get("UniversityDegreeCredential")
            .expect("UniversityDegreeCredential not found");
        assert_eq!(config.scope.as_deref(), Some("UniversityDegree"));

        let sd = match &config.format_details {
            CredentialFormatDetails::DcSdJwt(sd) => sd,
            other => panic!("expected DcSdJwt, got {other:?}"),
        };
        assert_eq!(
            sd.vct,
            "https://credentials.example.com/identity/UniversityDegree"
        );

        // Binding methods → proof types
        let binding = config
            .cryptographic_binding_methods_supported
            .as_ref()
            .unwrap();
        assert!(binding.contains(&"jwk".to_string()));

        let proof_types = config.proof_types_supported.as_ref().unwrap();
        let jwt_proof = proof_types.get("jwt").expect("jwt proof type not found");
        assert!(
            jwt_proof
                .proof_signing_alg_values_supported
                .contains(&"ES256".to_string())
        );

        // Credential display
        let cred_display = config.display.as_ref().unwrap();
        assert_eq!(cred_display[0].background_color.as_deref(), Some("#12107c"));
        assert_eq!(cred_display[0].text_color.as_deref(), Some("#FFFFFF"));
    }

    // ── ISO mdoc example ─────────────────────────────────────────────────────

    #[test]
    fn full_mdoc_example_parses() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "mDL": {
                    "format": "mso_mdoc",
                    "doctype": "org.iso.18013.5.1.mDL",
                    "cryptographic_binding_methods_supported": ["case_key"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {
                        "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("parse mdoc metadata");
        metadata.validate().expect("validate mdoc metadata");

        let config = metadata
            .credential_configurations_supported
            .get("mDL")
            .unwrap();
        let mdoc = match &config.format_details {
            CredentialFormatDetails::MsoMdoc(m) => m,
            other => panic!("expected MsoMdoc, got {other:?}"),
        };
        assert_eq!(mdoc.doctype, "org.iso.18013.5.1.mDL");
    }

    // ── W3C VC JWT example ────────────────────────────────────────────────────

    #[test]
    fn full_jwt_vc_json_example_parses() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "UniversityDegree": {
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                        "credentialSubject": {
                            "given_name": {},
                            "family_name": {}
                        }
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("parse jwt_vc_json metadata");
        metadata.validate().expect("validate jwt_vc_json metadata");

        let config = metadata
            .credential_configurations_supported
            .get("UniversityDegree")
            .unwrap();
        let jwt = match &config.format_details {
            CredentialFormatDetails::JwtVcJson(j) => j,
            other => panic!("expected JwtVcJson, got {other:?}"),
        };
        assert!(
            jwt.credential_definition
                .types
                .contains(&"UniversityDegreeCredential".to_string())
        );
        assert!(jwt.credential_definition.credential_subject.is_some());
    }

    // ── Validation failures ───────────────────────────────────────────────────

    #[test]
    fn validation_rejects_non_https_credential_endpoint() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "http://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": { "format": "dc+sd-jwt", "vct": "https://example.com/vct" }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        let err = metadata
            .validate()
            .expect_err("expected https validation failure");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(err.to_string().contains("credential_endpoint"));
    }

    #[test]
    fn validation_rejects_non_https_nonce_endpoint() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "nonce_endpoint": "http://issuer.example.com/nonce",
            "credential_configurations_supported": {
                "ExampleCredential": { "format": "dc+sd-jwt", "vct": "https://example.com/vct" }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        let err = metadata
            .validate()
            .expect_err("expected https failure for nonce");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(err.to_string().contains("nonce_endpoint"));
    }

    #[test]
    fn validation_rejects_empty_credential_configurations() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {}
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        let err = metadata.validate().expect_err("expected empty map failure");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(
            err.to_string()
                .contains("credential_configurations_supported")
        );
    }

    #[test]
    fn validation_rejects_missing_proof_types_when_binding_present() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct",
                    "cryptographic_binding_methods_supported": ["jwk"]
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        let err = metadata
            .validate()
            .expect_err("expected proof_types constraint failure");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(err.to_string().contains("proof_types_supported"));
    }

    #[test]
    fn validation_passes_when_binding_and_proof_types_both_set() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct",
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "proof_types_supported": {
                        "jwt": { "proof_signing_alg_values_supported": ["ES256"] }
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        assert!(metadata.validate().is_ok());
    }

    #[test]
    fn validation_passes_when_neither_binding_nor_proof_types_set() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct"
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).expect("deserialize");
        assert!(metadata.validate().is_ok());
    }

    // ── Display field parsing ─────────────────────────────────────────────────

    #[test]
    fn display_fields_parse_correctly() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "display": [
                { "name": "My Issuer", "locale": "de", "logo": { "uri": "https://my.logo/img.png" } },
                { "name": "My Issuer", "locale": "en" }
            ],
            "credential_configurations_supported": {
                "SomeCred": { "format": "dc+sd-jwt", "vct": "https://example.com/vct" }
            }
        });
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("deserialize display");
        let display = metadata.display.unwrap();
        assert_eq!(display.len(), 2);
        assert_eq!(display[0].locale.as_deref(), Some("de"));
        let logo = display[0].logo.as_ref().unwrap();
        assert_eq!(logo.uri, "https://my.logo/img.png");
        assert!(logo.alt_text.is_none());
        assert!(display[1].logo.is_none());
    }

    // ── Batch issuance ────────────────────────────────────────────────────────

    #[test]
    fn batch_credential_issuance_parsed() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "batch_credential_issuance": { "batch_size": 5 },
            "credential_configurations_supported": {
                "SomeCred": { "format": "dc+sd-jwt", "vct": "https://example.com/vct" }
            }
        });
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("deserialize batch info");
        let batch = metadata.batch_credential_issuance.unwrap();
        assert_eq!(batch.batch_size, 5);
    }

    // ── Multiple formats in one metadata document ─────────────────────────────

    #[test]
    fn metadata_with_multiple_format_types_parses() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "SDJWTcred": {
                    "format": "dc+sd-jwt",
                    "vct": "https://credentials.example.com/identity"
                },
                "MDLcred": {
                    "format": "mso_mdoc",
                    "doctype": "org.iso.18013.5.1.mDL"
                },
                "W3Ccred": {
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": ["VerifiableCredential", "UniversityDegreeCredential"]
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata =
            serde_json::from_value(json).expect("parse multi-format metadata");
        metadata.validate().expect("validate multi-format metadata");

        let configs = &metadata.credential_configurations_supported;
        assert!(matches!(
            configs["SDJWTcred"].format_details,
            CredentialFormatDetails::DcSdJwt(_)
        ));
        assert!(matches!(
            configs["MDLcred"].format_details,
            CredentialFormatDetails::MsoMdoc(_)
        ));
        assert!(matches!(
            configs["W3Ccred"].format_details,
            CredentialFormatDetails::JwtVcJson(_)
        ));
    }

    // ── key_attestations_required parsing ─────────────────────────────────────

    #[test]
    fn key_attestations_required_parses_correctly() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "HighAssuranceCred": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct",
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256"],
                            "key_attestations_required": {
                                "key_storage": ["iso_18045_moderate"],
                                "user_authentication": ["iso_18045_moderate"]
                            }
                        }
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
        metadata.validate().unwrap();

        let config = metadata
            .credential_configurations_supported
            .get("HighAssuranceCred")
            .unwrap();
        let proof_types = config.proof_types_supported.as_ref().unwrap();
        let jwt_proof = proof_types.get("jwt").unwrap();
        let key_att = jwt_proof.key_attestations_required.as_ref().unwrap();

        assert_eq!(
            key_att.key_storage.as_ref().unwrap()[0],
            "iso_18045_moderate"
        );
        assert_eq!(
            key_att.user_authentication.as_ref().unwrap()[0],
            "iso_18045_moderate"
        );
    }

    // ── credential_metadata nested structure ──────────────────────────────────

    #[test]
    fn sd_jwt_vc_credential_metadata_parses_correctly() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "UniversityDegree": {
                    "format": "dc+sd-jwt",
                    "vct": "https://credentials.example.com/UniversityDegree",
                    "credential_metadata": {
                        "display": [
                            {
                                "name": "University Degree",
                                "locale": "en-US"
                            }
                        ],
                        "claims": [
                            {
                                "path": ["given_name"],
                                "display": [{"locale": "en", "name": "Given Name"}],
                                "mandatory": true
                            },
                            {
                                "path": ["family_name"],
                                "display": [{"locale": "en", "name": "Family Name"}],
                                "mandatory": true
                            }
                        ]
                    }
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
        metadata.validate().unwrap();

        let config = metadata
            .credential_configurations_supported
            .get("UniversityDegree")
            .unwrap();
        let sd = match &config.format_details {
            CredentialFormatDetails::DcSdJwt(sd) => sd,
            other => panic!("expected DcSdJwt, got {other:?}"),
        };

        let cred_meta = sd.credential_metadata.as_ref().unwrap();
        assert_eq!(
            cred_meta.display.as_ref().unwrap()[0].name,
            Some("University Degree".to_string())
        );
        assert!(cred_meta.claims.is_some());
        let claims = cred_meta.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 2);
    }

    // ── authorization_servers validation ──────────────────────────────────────

    #[test]
    fn validation_passes_with_external_authorization_servers() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "authorization_servers": ["https://auth.example.com"],
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct"
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
        assert!(metadata.validate().is_ok());
    }

    #[test]
    fn validation_rejects_non_https_authorization_server() {
        let json = json!({
            "credential_issuer": "https://issuer.example.com",
            "authorization_servers": ["http://auth.example.com"],
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct"
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
        let err = metadata
            .validate()
            .expect_err("expected https failure for auth server");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(err.to_string().contains("authorization_servers"));
    }

    #[test]
    fn validation_rejects_non_https_credential_issuer_when_no_auth_servers() {
        let json = json!({
            "credential_issuer": "http://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "ExampleCredential": {
                    "format": "dc+sd-jwt",
                    "vct": "https://example.com/vct"
                }
            }
        });
        let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();
        let err = metadata
            .validate()
            .expect_err("expected https failure for issuer");
        assert_eq!(err.kind(), ErrorKind::InvalidIssuerMetadata);
        assert!(err.to_string().contains("credential_issuer"));
    }
}
