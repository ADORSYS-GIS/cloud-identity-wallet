#[cfg(feature = "schema-validation")]
use crate::errors::{Error, ErrorKind};
#[cfg(feature = "schema-validation")]
use crate::models::{Credential, CredentialPayload};
#[cfg(feature = "schema-validation")]
use crate::schema::CredentialValidationConfig;

/// Structural self-validation that a type can perform without external context.
pub trait Validatable {
    type Error;
    fn validate(&self) -> Result<(), Self::Error>;
}

/// Validates a credential's claims against the JSON Schema defined in a
/// [`CredentialValidationConfig`].
#[cfg(feature = "schema-validation")]
pub struct SchemaValidator;

#[cfg(feature = "schema-validation")]
impl SchemaValidator {
    /// Validates `credential`'s claims against the schema in `config`.
    pub fn validate_claims(
        credential: &Credential,
        config: &CredentialValidationConfig,
    ) -> Result<(), Error> {
        let Some(schema_value) = config.claims_schema() else {
            return Ok(());
        };
        let validator = Self::compile(schema_value)?;
        Self::run(&validator, credential, config)
    }

    /// Pre-compiles the JSON Schema from a configuration for reuse.
    pub fn compile_for(
        config: &CredentialValidationConfig,
    ) -> Result<Option<jsonschema::Validator>, Error> {
        match config.claims_schema() {
            Some(schema) => Self::compile(schema).map(Some),
            None => Ok(None),
        }
    }

    /// Validates `credential` using a pre-compiled [`jsonschema::Validator`].
    pub fn validate_with_compiled(
        credential: &Credential,
        config: &CredentialValidationConfig,
        validator: &jsonschema::Validator,
    ) -> Result<(), Error> {
        Self::run(validator, credential, config)
    }

    fn compile(schema: &serde_json::Value) -> Result<jsonschema::Validator, Error> {
        jsonschema::validator_for(schema).map_err(|e| Error::new(ErrorKind::InvalidSchema, e))
    }

    fn run(
        validator: &jsonschema::Validator,
        credential: &Credential,
        config: &CredentialValidationConfig,
    ) -> Result<(), Error> {
        let claims = match &credential.credential {
            CredentialPayload::MsoMdoc(mdoc) => {
                let Some(ns) = config.mdoc_claims_namespace() else {
                    return Ok(());
                };
                mdoc.claims(ns).ok_or_else(|| {
                    Error::message(
                        ErrorKind::SchemaMismatch,
                        format!(
                            "namespace '{ns}' not present in mdoc credential — config: {}",
                            config.credential_configuration_id
                        ),
                    )
                })?
            }
            _ => credential.credential.claims().ok_or_else(|| {
                Error::message(
                    ErrorKind::SchemaMismatch,
                    format!(
                        "no claims available for validation — config: {}",
                        config.credential_configuration_id
                    ),
                )
            })?,
        };

        let errors: Vec<String> = validator
            .iter_errors(claims)
            .map(|e| format!("{} (path: {})", e, e.instance_path))
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::message(
                ErrorKind::SchemaMismatch,
                format!(
                    "schema violations for config '{}':\n{}",
                    config.credential_configuration_id,
                    errors.join("\n")
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::Error;
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use crate::models::{
        Credential, CredentialId, CredentialPayload, CredentialStatus, SdJwtCredential,
    };

    fn sd_jwt_credential(claims: serde_json::Value) -> Result<Credential, Error> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            CredentialPayload::DcSdJwt(SdJwtCredential {
                token: "t".to_owned(),
                vct: "https://credentials.example.com/identity".to_owned(),
                claims,
            }),
        )
    }

    // Validate trait — impl lives in models.rs, tested here for coverage

    #[test]
    fn validate_trait_passes_for_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
        use crate::validation::Validatable;
        let cred = sd_jwt_credential(json!({}))?;
        assert!(cred.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_trait_catches_blank_issuer() {
        use crate::validation::Validatable;
        let cred = Credential {
            id: CredentialId::new(),
            issuer: "  ".to_owned(),
            subject: "user-1234".to_owned(),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_configuration_id: "cfg".to_owned(),
            credential: CredentialPayload::DcSdJwt(SdJwtCredential {
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
        use crate::errors::ErrorKind;
        use crate::models::{MsoMdocCredential, W3cVcJwtCredential};
        use crate::schema::CredentialValidationConfig;
        use crate::validation::SchemaValidator;

        fn w3c_credential(subject: serde_json::Value) -> Result<Credential, Error> {
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                OffsetDateTime::now_utc(),
                None,
                "university_degree",
                CredentialPayload::JwtVcJson(W3cVcJwtCredential {
                    token: "t".to_owned(),
                    credential_type: vec!["VerifiableCredential".to_owned()],
                    credential_subject: subject,
                }),
            )
        }

        fn mdoc_credential(
            namespace: &str,
            claims: serde_json::Value,
        ) -> Result<Credential, Error> {
            let mut namespaces = std::collections::HashMap::new();
            namespaces.insert(namespace.to_owned(), claims);
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                OffsetDateTime::now_utc(),
                Some(OffsetDateTime::now_utc() + Duration::days(365)),
                "mdl_credential",
                CredentialPayload::MsoMdoc(MsoMdocCredential {
                    doc_type: "org.iso.18013.5.1.mDL".to_owned(),
                    namespaces,
                    issuer_signed: "base64url-mso".to_owned(),
                }),
            )
        }

        fn config_with_schema(schema: serde_json::Value) -> CredentialValidationConfig {
            CredentialValidationConfig {
                credential_configuration_id: "identity_credential".to_owned(),
                claims_schema: Some(schema),
                mdoc_claims_namespace: None,
            }
        }

        fn config_without_schema() -> CredentialValidationConfig {
            CredentialValidationConfig {
                credential_configuration_id: "identity_credential".to_owned(),
                claims_schema: None,
                mdoc_claims_namespace: None,
            }
        }

        /// Schema for identity credentials.
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

        /// Schema for ISO mDL (mdoc) namespace claims.
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
        ) -> CredentialValidationConfig {
            CredentialValidationConfig {
                credential_configuration_id: "mdl_credential".to_owned(),
                claims_schema: Some(schema),
                mdoc_claims_namespace: Some(namespace.to_owned()),
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

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for missing family_name");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("family_name"),
                "unexpected error: {err}"
            );
            Ok(())
        }

        #[test]
        fn wrong_type_fails_validation() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({ "given_name": 42, "family_name": "Smith" }))?;

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for wrong type on given_name");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("given_name"),
                "unexpected error: {err}"
            );
            Ok(())
        }

        #[test]
        fn additional_properties_blocked_when_schema_disallows()
        -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(
                json!({ "given_name": "Alice", "family_name": "Smith", "extra": "bad" }),
            )?;

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for disallowed additional property");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("extra"),
                "unexpected error: {err}"
            );
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
            let config = CredentialValidationConfig {
                credential_configuration_id: "university_degree".to_owned(),
                claims_schema: Some(schema),
                mdoc_claims_namespace: None,
            };

            let valid = w3c_credential(json!({ "degree": "BSc", "institution": "Uni" }))?;
            assert!(SchemaValidator::validate_claims(&valid, &config).is_ok());

            let invalid = w3c_credential(json!({ "degree": "BSc" }))?;
            let err = SchemaValidator::validate_claims(&invalid, &config)
                .expect_err("expected a schema mismatch for missing institution");
            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("institution"),
                "unexpected error: {err}"
            );
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

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for missing given_name");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("given_name"),
                "unexpected error: {err}"
            );
            Ok(())
        }

        #[test]
        fn mdoc_absent_namespace_returns_mismatch() -> Result<(), Box<dyn std::error::Error>> {
            let config = mdoc_config_with_namespace("org.iso.18013.5.1", mdl_schema());
            let cred = mdoc_credential(
                "org.iso.18013.5.1.aamva",
                json!({ "family_name": "Smith", "given_name": "Alice" }),
            )?;

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for absent namespace");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch
                    && err.to_string().contains("org.iso.18013.5.1"),
                "unexpected error: {err}"
            );
            Ok(())
        }

        #[test]
        fn mdoc_without_namespace_in_config_passes() -> Result<(), Box<dyn std::error::Error>> {
            let config = CredentialValidationConfig {
                credential_configuration_id: "mdl_credential".to_owned(),
                claims_schema: Some(mdl_schema()),
                mdoc_claims_namespace: None, // no namespace — validator skips mdoc claims
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

            let err = SchemaValidator::validate_with_compiled(&invalid, &config, &validator)
                .expect_err("expected a schema mismatch for missing family_name");
            assert!(
                err.kind() == ErrorKind::SchemaMismatch && err.to_string().contains("family_name"),
                "unexpected error: {err}"
            );
            Ok(())
        }

        #[test]
        fn compile_for_config_without_schema_returns_none() -> Result<(), Error> {
            let config = config_without_schema();
            let result = SchemaValidator::compile_for(&config)?;
            assert!(result.is_none());
            Ok(())
        }

        #[test]
        fn all_violations_reported_together() -> Result<(), Box<dyn std::error::Error>> {
            let config = config_with_schema(identity_schema());
            let cred = sd_jwt_credential(json!({}))?;

            let err = SchemaValidator::validate_claims(&cred, &config)
                .expect_err("expected a schema mismatch for empty claims");

            assert!(
                err.kind() == ErrorKind::SchemaMismatch
                    && err.to_string().contains("given_name")
                    && err.to_string().contains("family_name"),
                "expected both missing field names to be reported; got: {err}"
            );
            Ok(())
        }
    }
}
