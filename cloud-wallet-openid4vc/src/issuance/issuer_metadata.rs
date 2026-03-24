//! Credential Issuer Metadata.
//!
//! See [spec].
//!
//! [spec]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use url::Url;
use validator::Validate;

use crate::errors::{Error, ErrorKind};

use super::credential_configuration::{CredentialConfiguration, Logo};

/// Per-language display properties for the Credential Issuer.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuerDisplay {
    /// Human-readable display name of the Credential Issuer.
    pub name: Option<String>,

    /// BCP47 language tag (e.g. `"en-US"`).
    pub locale: Option<String>,

    /// Optional logo for the Credential Issuer.
    pub logo: Option<Logo>,
}

/// Encryption settings for Credential Request encryption.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequestEncryption {
    /// JSON Web Key Set containing public keys for key agreement.
    pub jwks: Value,
    pub enc_values_supported: Vec<String>,

    /// JWE `zip` compression algorithm values supported.
    pub zip_values_supported: Option<Vec<String>>,
    /// If true, encryption is required for every request.
    pub encryption_required: bool,
}

/// Encryption settings for Credential Response encryption.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub zip_values_supported: Option<Vec<String>>,
    /// If true, the Wallet MUST provide encryption keys in the Credential Request.
    pub encryption_required: bool,
}

/// Batch credential issuance support.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
pub struct BatchCredentialIssuance {
    /// Maximum size of the `proofs` array (MUST be >= 2).
    #[validate(range(min = 2, message = "batch_size must be at least 2"))]
    pub batch_size: u32,
}

/// The Credential Issuer Metadata document.
///
/// Served at `/.well-known/openid-credential-issuer`. Call [`validate`](Self::validate)
/// after deserialization to enforce HTTPS requirements.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: Url,
    pub authorization_servers: Option<Vec<Url>>,
    pub credential_endpoint: Url,
    pub nonce_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub notification_endpoint: Option<Url>,
    pub batch_credential_endpoint: Option<Url>,
    pub credential_request_encryption: Option<CredentialRequestEncryption>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    pub display: Option<Vec<IssuerDisplay>>,
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
}

impl CredentialIssuerMetadata {
    /// Validates spec requirements (HTTPS URLs, non-empty configs, etc.).
    pub fn validate(&self) -> Result<(), Error> {
        require_https(&self.credential_endpoint, "credential_endpoint")?;

        for (field, url) in [
            ("nonce_endpoint", self.nonce_endpoint.as_ref()),
            (
                "deferred_credential_endpoint",
                self.deferred_credential_endpoint.as_ref(),
            ),
            ("notification_endpoint", self.notification_endpoint.as_ref()),
            (
                "batch_credential_endpoint",
                self.batch_credential_endpoint.as_ref(),
            ),
        ] {
            if let Some(url) = url {
                require_https(url, field)?;
            }
        }

        if self.credential_configurations_supported.is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidIssuerMetadata,
                "credential_configurations_supported must contain at least one entry",
            ));
        }

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

            // Validate non-empty proof_signing_alg_values_supported
            if let Some(proof_types) = &config.proof_types_supported {
                for (proof_type, metadata) in proof_types {
                    if metadata.proof_signing_alg_values_supported.is_empty() {
                        return Err(Error::message(
                            ErrorKind::InvalidIssuerMetadata,
                            format!(
                                "credential configuration \"{id}\": proof_types_supported.\"{proof_type}\".proof_signing_alg_values_supported must be non-empty"
                            ),
                        ));
                    }
                }
            }
        }

        require_https(&self.credential_issuer, "credential_issuer")?;

        if let Some(auth_servers) = &self.authorization_servers {
            for auth_server in auth_servers {
                require_https(auth_server, "authorization_servers entry")?;
            }
        }

        if let Some(batch) = &self.batch_credential_issuance {
            batch.validate().map_err(|e| {
                Error::message(
                    ErrorKind::InvalidIssuerMetadata,
                    format!("batch_credential_issuance validation failed: {e}"),
                )
            })?;
        }

        Ok(())
    }
}

/// Returns an error if `url` does not use the `https` scheme.
fn require_https(url: &Url, field: &str) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::credential_formats::{
        CredentialDefinition, CredentialFormatDetails, JwtVcJsonCredentialConfiguration,
        MsoMdocCredentialConfiguration, SdJwtVcCredentialConfiguration,
    };
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

    /// Full issuer metadata from Keycloak OID4VCI deployment.
    /// Source: ngrok tunnel to Keycloak realm with OID4VCI enabled.
    const KEYCLOAK_METADATA: &str = include_str!("../../tests_metadata/issuer_metadata.json");

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
            credential_definition: None,
            claims: None,
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
                context: None,
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
        assert_eq!(
            metadata.credential_issuer.as_str(),
            "https://issuer.example.com/"
        );
        assert_eq!(
            metadata.credential_endpoint.as_str(),
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
                    "credential_metadata": {
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
        assert_eq!(auth_servers[0].as_str(), "https://server.example.com/");

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
                .iter()
                .any(|alg| alg.as_str() == "ES256")
        );

        // Credential display (via credential_metadata)
        let cred_meta = config.credential_metadata.as_ref().unwrap();
        let cred_display = cred_meta.display.as_ref().unwrap();
        assert_eq!(
            cred_display[0]
                .background_color
                .as_ref()
                .map(|c| c.as_str()),
            Some("#12107c")
        );
        assert_eq!(
            cred_display[0].text_color.as_ref().map(|c| c.as_str()),
            Some("#FFFFFF")
        );
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
        assert_eq!(logo.uri.as_str(), "https://my.logo/img.png");
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

        let cred_meta = config.credential_metadata.as_ref().unwrap();
        assert_eq!(
            cred_meta.display.as_ref().unwrap()[0].name,
            "University Degree"
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

    /// Tests that Keycloak issuer metadata can be deserialized and validated.
    ///
    /// Note: This test does not perform a full round-trip comparison because:
    /// - The `id` field in credential configurations is not part of the spec and is ignored
    /// - URL fields are now typed as `Url` which may normalize the string representation
    #[test]
    fn keycloak_issuer_metadata_round_trip() {
        // Deserialize into typed struct
        let metadata: CredentialIssuerMetadata = serde_json::from_str(KEYCLOAK_METADATA)
            .expect("failed to deserialize into CredentialIssuerMetadata");

        // Validate the metadata
        metadata.validate().expect("metadata validation failed");

        // Verify we parsed both credential configurations
        assert_eq!(metadata.credential_configurations_supported.len(), 2);
        assert!(
            metadata
                .credential_configurations_supported
                .contains_key("oid4vc_natural_person")
        );
        assert!(
            metadata
                .credential_configurations_supported
                .contains_key("IdentityCredential")
        );

        // Verify encryption settings
        assert!(metadata.credential_response_encryption.is_some());
        assert!(metadata.credential_request_encryption.is_some());

        // Verify the struct can be serialized back to valid JSON
        let serialized: serde_json::Value =
            serde_json::to_value(&metadata).expect("failed to serialize back to JSON");

        // Verify essential fields are present in serialized output
        assert!(serialized.get("credential_issuer").is_some());
        assert!(serialized.get("credential_endpoint").is_some());
        assert!(
            serialized
                .get("credential_configurations_supported")
                .is_some()
        );
    }
}
