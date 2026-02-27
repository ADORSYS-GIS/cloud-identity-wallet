use serde::{Deserialize, Serialize};

/// The credential format identifier string as defined by OpenID4VCI Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormatIdentifier {
    /// IETF SD-JWT VC — wire value `"vc+sd-jwt"`
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt,

    /// ISO 18013-5 mdoc — wire value `"mso_mdoc"`
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,

    /// W3C VC signed as a JWT, not using JSON-LD — wire value `"jwt_vc_json"`
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
}

/// Display metadata for a credential configuration (§12.2.4 `display` array).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoImage>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// A logo image reference within [`CredentialDisplay`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoImage {
    pub uri: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// Format-specific parameters required inside a [`CredentialConfiguration`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialDefinition {
    SdJwt {
        vct: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        claims_schema: Option<serde_json::Value>,
    },

    MsoMdoc {
        doctype: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        claims_schema: Option<serde_json::Value>,
    },

    JwtVcJson {
        credential_definition: JwtVcCredentialDefinition,

        #[serde(skip_serializing_if = "Option::is_none")]
        claims_schema: Option<serde_json::Value>,
    },
}

/// The `credential_definition` object for `jwt_vc_json` format profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVcCredentialDefinition {
    #[serde(rename = "type")]
    pub types: Vec<String>,
}

/// Issuer's description of a particular kind of credential it can issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: CredentialFormatIdentifier,

    pub credential_definition: CredentialDefinition,

    #[serde(default)]
    pub cryptographic_binding_methods_supported: Vec<String>,

    #[serde(default)]
    pub credential_signing_alg_values_supported: Vec<String>,

    #[serde(default)]
    pub display: Vec<CredentialDisplay>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl CredentialConfiguration {
    /// Returns the JSON Schema for the credential's claims, if one is defined.
    pub fn claims_schema(&self) -> Option<&serde_json::Value> {
        match &self.credential_definition {
            CredentialDefinition::SdJwt { claims_schema, .. } => claims_schema.as_ref(),
            CredentialDefinition::MsoMdoc { claims_schema, .. } => claims_schema.as_ref(),
            CredentialDefinition::JwtVcJson { claims_schema, .. } => claims_schema.as_ref(),
        }
    }

    /// Returns the format identifier string for this configuration.
    pub fn format_identifier(&self) -> &CredentialFormatIdentifier {
        &self.format
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sd_jwt_config() -> CredentialConfiguration {
        CredentialConfiguration {
            format: CredentialFormatIdentifier::VcSdJwt,
            credential_definition: CredentialDefinition::SdJwt {
                vct: "https://credentials.example.com/identity_credential".to_owned(),
                claims_schema: Some(json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {
                        "given_name": { "type": "string" },
                        "family_name": { "type": "string" },
                        "birthdate": { "type": "string" }
                    },
                    "required": ["given_name", "family_name"]
                })),
            },
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            display: vec![CredentialDisplay {
                name: "Identity Credential".to_owned(),
                locale: Some("en-US".to_owned()),
                logo: None,
                background_color: Some("#12107c".to_owned()),
                text_color: Some("#FFFFFF".to_owned()),
            }],
            scope: Some("identity_credential".to_owned()),
        }
    }

    fn mdoc_config() -> CredentialConfiguration {
        CredentialConfiguration {
            format: CredentialFormatIdentifier::MsoMdoc,
            credential_definition: CredentialDefinition::MsoMdoc {
                doctype: "org.iso.18013.5.1.mDL".to_owned(),
                claims_schema: None,
            },
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            display: vec![],
            scope: None,
        }
    }

    fn jwt_vc_config() -> CredentialConfiguration {
        CredentialConfiguration {
            format: CredentialFormatIdentifier::JwtVcJson,
            credential_definition: CredentialDefinition::JwtVcJson {
                credential_definition: JwtVcCredentialDefinition {
                    types: vec![
                        "VerifiableCredential".to_owned(),
                        "UniversityDegreeCredential".to_owned(),
                    ],
                },
                claims_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "degree": { "type": "string" },
                        "institution": { "type": "string" }
                    },
                    "required": ["degree", "institution"]
                })),
            },
            cryptographic_binding_methods_supported: vec!["did:key".to_owned()],
            credential_signing_alg_values_supported: vec!["EdDSA".to_owned()],
            display: vec![],
            scope: None,
        }
    }

    // CredentialFormatIdentifier serialization

    #[test]
    fn format_identifier_serializes_to_spec_wire_values() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&CredentialFormatIdentifier::VcSdJwt)?,
            r#""vc+sd-jwt""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialFormatIdentifier::MsoMdoc)?,
            r#""mso_mdoc""#
        );
        assert_eq!(
            serde_json::to_string(&CredentialFormatIdentifier::JwtVcJson)?,
            r#""jwt_vc_json""#
        );
        Ok(())
    }

    #[test]
    fn format_identifier_deserializes_from_spec_wire_values() -> Result<(), serde_json::Error> {
        let sd: CredentialFormatIdentifier = serde_json::from_str(r#""vc+sd-jwt""#)?;
        assert_eq!(sd, CredentialFormatIdentifier::VcSdJwt);

        let mdoc: CredentialFormatIdentifier = serde_json::from_str(r#""mso_mdoc""#)?;
        assert_eq!(mdoc, CredentialFormatIdentifier::MsoMdoc);

        let jwt: CredentialFormatIdentifier = serde_json::from_str(r#""jwt_vc_json""#)?;
        assert_eq!(jwt, CredentialFormatIdentifier::JwtVcJson);
        Ok(())
    }

    // CredentialConfiguration construction

    #[test]
    fn sd_jwt_config_claims_schema_accessible() {
        let config = sd_jwt_config();
        assert!(config.claims_schema().is_some());
    }

    #[test]
    fn mdoc_config_without_schema_returns_none() {
        let config = mdoc_config();
        assert!(config.claims_schema().is_none());
    }

    #[test]
    fn jwt_vc_config_has_correct_types() {
        let config = jwt_vc_config();
        let CredentialDefinition::JwtVcJson {
            credential_definition,
            ..
        } = &config.credential_definition
        else {
            // This would indicate a bug in the test fixture itself
            return;
        };
        assert!(
            credential_definition
                .types
                .contains(&"VerifiableCredential".to_owned())
        );
        assert!(
            credential_definition
                .types
                .contains(&"UniversityDegreeCredential".to_owned())
        );
    }

    // Round-trip serialization

    #[test]
    fn sd_jwt_config_round_trips_through_json() -> Result<(), serde_json::Error> {
        let config = sd_jwt_config();
        let json = serde_json::to_string(&config)?;
        let restored: CredentialConfiguration = serde_json::from_str(&json)?;
        assert_eq!(restored.format, CredentialFormatIdentifier::VcSdJwt);
        assert_eq!(restored.scope, Some("identity_credential".to_owned()));
        Ok(())
    }

    #[test]
    fn mdoc_config_round_trips_through_json() -> Result<(), serde_json::Error> {
        let config = mdoc_config();
        let json = serde_json::to_string(&config)?;
        let restored: CredentialConfiguration = serde_json::from_str(&json)?;
        assert_eq!(restored.format, CredentialFormatIdentifier::MsoMdoc);
        Ok(())
    }

    #[test]
    fn display_fields_serialize_correctly() -> Result<(), serde_json::Error> {
        let config = sd_jwt_config();
        let json_val = serde_json::to_value(&config)?;
        let display = &json_val["display"][0];
        assert_eq!(display["name"], "Identity Credential");
        assert_eq!(display["locale"], "en-US");
        assert_eq!(display["background_color"], "#12107c");
        Ok(())
    }

    #[test]
    fn none_fields_are_omitted_from_serialization() -> Result<(), serde_json::Error> {
        let config = mdoc_config();
        let json_val = serde_json::to_value(&config)?;
        // scope is None, should not appear in JSON
        assert!(json_val.get("scope").is_none());
        Ok(())
    }
}
