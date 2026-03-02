use crate::errors::ValidationError;
use crate::models::Credential;
#[cfg(feature = "schema-validation")]
use crate::schema::CredentialConfiguration;
/// Structural self-validation that a type can perform without external context.
pub trait Validate {
    type Error;
    fn validate(&self) -> Result<(), Self::Error>;
}

impl Validate for Credential {
    type Error = ValidationError;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_structure()
    }
}

/// Validates a credential's claims against the JSON Schema defined in a
/// [`CredentialConfiguration`].
#[cfg(feature = "schema-validation")]
pub struct SchemaValidator;

#[cfg(feature = "schema-validation")]
impl SchemaValidator {
    /// Validates `credential`'s claims against the schema in `config`.
    pub fn validate_claims(
        credential: &Credential,
        config: &CredentialConfiguration,
    ) -> Result<(), ValidationError> {
        let Some(schema_value) = config.claims_schema() else {
            return Ok(());
        };
        let validator = Self::compile(schema_value)?;
        Self::run(&validator, credential, config)
    }

    /// Pre-compiles the JSON Schema from a configuration for reuse.
    pub fn compile_for(
        config: &CredentialConfiguration,
    ) -> Result<Option<jsonschema::Validator>, ValidationError> {
        match config.claims_schema() {
            Some(schema) => Self::compile(schema).map(Some),
            None => Ok(None),
        }
    }

    /// Validates `credential` using a pre-compiled [`jsonschema::Validator`].
    pub fn validate_with_compiled(
        credential: &Credential,
        config: &CredentialConfiguration,
        validator: &jsonschema::Validator,
    ) -> Result<(), ValidationError> {
        Self::run(validator, credential, config)
    }

    fn compile(schema: &serde_json::Value) -> Result<jsonschema::Validator, ValidationError> {
        jsonschema::validator_for(schema).map_err(|e| ValidationError::InvalidJsonSchema {
            reason: e.to_string(),
        })
    }

    fn run(
        validator: &jsonschema::Validator,
        credential: &Credential,
        config: &CredentialConfiguration,
    ) -> Result<(), ValidationError> {
        use crate::models::CredentialFormat;

        // Resolve which claims value to validate against.
        let claims = match &credential.format {
            CredentialFormat::MsoMdoc(mdoc) => {
                let Some(ns) = config.mdoc_claims_namespace() else {
                    return Ok(());
                };
                mdoc.claims_for_namespace(ns)
                    .ok_or_else(|| ValidationError::SchemaMismatch {
                        schema_id: format!("{:?}", config.format),
                        details: format!("namespace '{ns}' not present in mdoc credential"),
                    })?
            }
            _ => credential
                .format
                .claims()
                .ok_or_else(|| ValidationError::SchemaMismatch {
                    schema_id: format!("{:?}", config.format),
                    details: "no claims available for validation".to_owned(),
                })?,
        };

        let errors: Vec<String> = validator
            .iter_errors(claims)
            .map(|e| format!("{} (path: {})", e, e.instance_path))
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::SchemaMismatch {
                schema_id: format!("{:?}", config.format),
                details: errors.join("\n"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use crate::models::{Credential, CredentialFormat, CredentialStatus, SdJwtCredential};

    fn sd_jwt_credential(claims: serde_json::Value) -> Result<Credential, ValidationError> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            CredentialFormat::VcSdJwt(SdJwtCredential {
                token: "t".to_owned(),
                vct: "https://credentials.example.com/identity".to_owned(),
                claims,
            }),
        )
    }

    // Validate trait

    #[test]
    fn validate_trait_passes_for_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
        let cred = sd_jwt_credential(json!({}))?;
        assert!(cred.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_trait_catches_blank_issuer() {
        let cred = Credential {
            id: crate::models::CredentialId::new(),
            issuer: "  ".to_owned(),
            subject: "user-1234".to_owned(),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_configuration_id: "cfg".to_owned(),
            format: CredentialFormat::VcSdJwt(SdJwtCredential {
                token: "t".to_owned(),
                vct: "vct".to_owned(),
                claims: json!({}),
            }),
            status: CredentialStatus::Active,
        };
        assert!(cred.validate().is_err());
    }

    // SchemaValidator (requires schema-validation feature)

    #[cfg(feature = "schema-validation")]
    mod schema_validator_tests {
        use super::*;
        use crate::models::{MsoMdocCredential, W3cVcJwtCredential};
        use crate::schema::{
            CredentialConfiguration, CredentialDefinition, CredentialFormatIdentifier,
        };

        fn w3c_credential(subject: serde_json::Value) -> Result<Credential, ValidationError> {
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                OffsetDateTime::now_utc(),
                None,
                "university_degree",
                CredentialFormat::JwtVcJson(W3cVcJwtCredential {
                    token: "t".to_owned(),
                    credential_type: vec!["VerifiableCredential".to_owned()],
                    credential_subject: subject,
                }),
            )
        }

        fn mdoc_credential(
            namespace: &str,
            claims: serde_json::Value,
        ) -> Result<Credential, ValidationError> {
            let mut namespaces = std::collections::HashMap::new();
            namespaces.insert(namespace.to_owned(), claims);
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                OffsetDateTime::now_utc(),
                Some(OffsetDateTime::now_utc() + Duration::days(365)),
                "mdl_credential",
                CredentialFormat::MsoMdoc(MsoMdocCredential {
                    doc_type: "org.iso.18013.5.1.mDL".to_owned(),
                    namespaces,
                    issuer_signed: "base64url-mso".to_owned(),
                }),
            )
        }

        fn config_with_schema(schema: serde_json::Value) -> CredentialConfiguration {
            CredentialConfiguration {
                format: CredentialFormatIdentifier::VcSdJwt,
                credential_definition: CredentialDefinition::SdJwt {
                    vct: "https://credentials.example.com/identity".to_owned(),
                    claims_schema: Some(schema),
                },
                cryptographic_binding_methods_supported: vec![],
                credential_signing_alg_values_supported: vec![],
                display: vec![],
                scope: None,
            }
        }

        fn config_without_schema() -> CredentialConfiguration {
            CredentialConfiguration {
                format: CredentialFormatIdentifier::VcSdJwt,
                credential_definition: CredentialDefinition::SdJwt {
                    vct: "https://credentials.example.com/identity".to_owned(),
                    claims_schema: None,
                },
                cryptographic_binding_methods_supported: vec![],
                credential_signing_alg_values_supported: vec![],
                display: vec![],
                scope: None,
            }
        }

        fn identity_schema() -> serde_json::Value {
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "given_name": { "type": "string" },
                    "family_name": { "type": "string" }
                },
                "required": ["given_name", "family_name"],
                "additionalProperties": false
            })
        }

        fn mdl_schema() -> serde_json::Value {
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "family_name": { "type": "string" },
                    "given_name": { "type": "string" }
                },
                "required": ["family_name", "given_name"]
            })
        }

        fn mdoc_config_with_namespace(
            namespace: &str,
            schema: serde_json::Value,
        ) -> CredentialConfiguration {
            CredentialConfiguration {
                format: CredentialFormatIdentifier::MsoMdoc,
                credential_definition: CredentialDefinition::MsoMdoc {
                    doctype: "org.iso.18013.5.1.mDL".to_owned(),
                    claims_namespace: Some(namespace.to_owned()),
                    claims_schema: Some(schema),
                },
                cryptographic_binding_methods_supported: vec![],
                credential_signing_alg_values_supported: vec![],
                display: vec![],
                scope: None,
            }
        }

        #[test]
        fn valid_claims_pass_validation() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({ "given_name": "Alice", "family_name": "Smith" }))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_ok());
            Ok(())
        }

        #[test]
        fn missing_required_field_fails() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({ "given_name": "Alice" }))?;
            let result = SchemaValidator::validate_claims(&cred, &config);
            assert!(result.is_err());
            if let Err(ValidationError::SchemaMismatch { details, .. }) = result {
                assert!(details.contains("family_name"));
            }
            Ok(())
        }

        #[test]
        fn wrong_type_fails_validation() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({ "given_name": 42, "family_name": "Smith" }))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_err());
            Ok(())
        }

        #[test]
        fn additional_properties_blocked_when_schema_disallows()
        -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(
                json!({ "given_name": "Alice", "family_name": "Smith", "extra": "bad" }),
            )?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_err());
            Ok(())
        }

        #[test]
        fn config_without_schema_always_passes() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_without_schema();
            let cred = sd_jwt_credential(json!({}))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_ok());
            Ok(())
        }

        #[test]
        fn w3c_credential_validated_against_schema() -> Result<(), Box<dyn std::error::Error>> {
            let schema = json!({
                "type": "object",
                "properties": {
                    "degree": { "type": "string" },
                    "institution": { "type": "string" }
                },
                "required": ["degree", "institution"]
            });
            let config = CredentialConfiguration {
                format: CredentialFormatIdentifier::JwtVcJson,
                credential_definition: CredentialDefinition::JwtVcJson {
                    credential_definition: crate::schema::JwtVcCredentialDefinition {
                        types: vec!["VerifiableCredential".to_owned()],
                    },
                    claims_schema: Some(schema),
                },
                cryptographic_binding_methods_supported: vec![],
                credential_signing_alg_values_supported: vec![],
                display: vec![],
                scope: None,
            };

            let valid = w3c_credential(json!({ "degree": "BSc", "institution": "Uni" }))?;
            assert!(SchemaValidator::validate_claims(&valid, &config).is_ok());

            let invalid = w3c_credential(json!({ "degree": "BSc" }))?;
            assert!(SchemaValidator::validate_claims(&invalid, &config).is_err());
            Ok(())
        }

        #[test]
        fn mdoc_valid_namespace_claims_pass() -> Result<(), Box<dyn std::error::Error>> {
            let ns = "org.iso.18013.5.1";
            let config = mdoc_config_with_namespace(ns, mdl_schema());
            let cred =
                mdoc_credential(ns, json!({ "family_name": "Smith", "given_name": "Alice" }))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_ok());
            Ok(())
        }

        #[test]
        fn mdoc_missing_required_field_in_namespace_fails() -> Result<(), Box<dyn std::error::Error>>
        {
            let ns = "org.iso.18013.5.1";
            let config = mdoc_config_with_namespace(ns, mdl_schema());
            let cred = mdoc_credential(ns, json!({ "family_name": "Smith" }))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_err());
            Ok(())
        }

        #[test]
        fn mdoc_absent_namespace_returns_mismatch() -> Result<(), Box<dyn std::error::Error>> {
            let config = mdoc_config_with_namespace("org.iso.18013.5.1", mdl_schema());
            // Credential only has a different namespace
            let cred = mdoc_credential(
                "org.iso.18013.5.1.aamva",
                json!({ "family_name": "Smith", "given_name": "Alice" }),
            )?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_err());
            Ok(())
        }

        #[test]
        fn mdoc_without_namespace_in_config_passes() -> Result<(), Box<dyn std::error::Error>> {
            // No claims_namespace set — validation should pass regardless of claims
            let config = CredentialConfiguration {
                format: CredentialFormatIdentifier::MsoMdoc,
                credential_definition: CredentialDefinition::MsoMdoc {
                    doctype: "org.iso.18013.5.1.mDL".to_owned(),
                    claims_namespace: None,
                    claims_schema: Some(mdl_schema()),
                },
                cryptographic_binding_methods_supported: vec![],
                credential_signing_alg_values_supported: vec![],
                display: vec![],
                scope: None,
            };
            let cred = mdoc_credential("org.iso.18013.5.1", json!({}))?;
            assert!(SchemaValidator::validate_claims(&cred, &config).is_ok());
            Ok(())
        }

        #[test]
        fn compiled_validator_reuse_works() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let validator =
                SchemaValidator::compile_for(&config)?.ok_or("expected a compiled validator")?;

            let valid = sd_jwt_credential(json!({ "given_name": "Bob", "family_name": "Jones" }))?;
            let invalid = sd_jwt_credential(json!({ "given_name": "Bob" }))?;

            assert!(SchemaValidator::validate_with_compiled(&valid, &config, &validator).is_ok());
            assert!(
                SchemaValidator::validate_with_compiled(&invalid, &config, &validator).is_err()
            );
            Ok(())
        }

        #[test]
        fn compile_for_config_without_schema_returns_none() -> Result<(), ValidationError> {
            let config = config_without_schema();
            let result = SchemaValidator::compile_for(&config)?;
            assert!(result.is_none());
            Ok(())
        }

        #[test]
        fn all_violations_reported_together() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({}))?;
            let result = SchemaValidator::validate_claims(&cred, &config);
            if let Err(ValidationError::SchemaMismatch { details, .. }) = result {
                assert!(
                    details.contains("given_name") || details.contains("family_name"),
                    "Expected missing field names in: {details}"
                );
            }
            Ok(())
        }
    }
}
