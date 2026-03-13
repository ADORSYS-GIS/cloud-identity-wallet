use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// The credential format identifier string as defined by OpenID4VCI Appendix A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormatIdentifier {
    /// IETF SD-JWT VC — wire value `"dc+sd-jwt"` (formerly `"vc+sd-jwt"`)
    #[serde(rename = "dc+sd-jwt")]
    VcSdJwt,

    /// ISO 18013-5 mdoc — wire value `"mso_mdoc"`
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,

    /// W3C VC signed as a JWT, not using JSON-LD — wire value `"jwt_vc_json"`
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
}

/// Display metadata for a credential configuration (§12.2.4 `display` array).
///
/// See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4>.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<Logo>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub background_image: Option<Image>,
    pub text_color: Option<String>,
}

/// A logo image reference within [`CredentialDisplay`].
///
/// Defined in OpenID4VCI §12.2.4.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logo {
    /// A URI pointing to the logo image.
    pub uri: url::Url,
    pub alt_text: Option<String>,
}

/// A background image reference within [`CredentialDisplay`].
///
/// Defined in OpenID4VCI §12.2.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Image {
    /// A URI pointing to the background image.
    pub uri: url::Url,
}

/// Issuer's description of a particular kind of credential it can issue.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: CredentialFormatIdentifier,

    #[serde(default)]
    pub cryptographic_binding_methods_supported: Vec<String>,

    #[serde(default)]
    pub credential_signing_alg_values_supported: Vec<String>,

    #[serde(default)]
    pub display: Vec<CredentialDisplay>,

    pub scope: Option<String>,
}

impl CredentialConfiguration {
    /// Returns the format identifier for this configuration.
    pub fn format_identifier(&self) -> &CredentialFormatIdentifier {
        &self.format
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sd_jwt_config() -> CredentialConfiguration {
        CredentialConfiguration {
            format: CredentialFormatIdentifier::VcSdJwt,
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            display: vec![CredentialDisplay {
                name: "Identity Credential".to_owned(),
                locale: Some("en-US".to_owned()),
                logo: None,
                description: Some("An identity credential issued by Example Corp.".to_owned()),
                background_color: Some("#12107c".to_owned()),
                background_image: None,
                text_color: Some("#FFFFFF".to_owned()),
            }],
            scope: Some("identity_credential".to_owned()),
        }
    }

    fn mdoc_config() -> CredentialConfiguration {
        CredentialConfiguration {
            format: CredentialFormatIdentifier::MsoMdoc,
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            display: vec![],
            scope: None,
        }
    }

    // CredentialFormatIdentifier serialization

    #[test]
    fn format_identifier_serializes_to_spec_wire_values() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&CredentialFormatIdentifier::VcSdJwt)?,
            r#""dc+sd-jwt""#
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
        let sd: CredentialFormatIdentifier = serde_json::from_str(r#""dc+sd-jwt""#)?;
        assert_eq!(sd, CredentialFormatIdentifier::VcSdJwt);

        let mdoc: CredentialFormatIdentifier = serde_json::from_str(r#""mso_mdoc""#)?;
        assert_eq!(mdoc, CredentialFormatIdentifier::MsoMdoc);

        let jwt: CredentialFormatIdentifier = serde_json::from_str(r#""jwt_vc_json""#)?;
        assert_eq!(jwt, CredentialFormatIdentifier::JwtVcJson);
        Ok(())
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
        assert_eq!(
            display["description"],
            "An identity credential issued by Example Corp."
        );
        assert_eq!(display["background_color"], "#12107c");
        assert_eq!(display["text_color"], "#FFFFFF");
        assert!(display.get("logo").is_none());
        assert!(display.get("background_image").is_none());
        Ok(())
    }

    #[test]
    fn none_fields_are_omitted_from_serialization() -> Result<(), serde_json::Error> {
        let config = mdoc_config();
        let json_val = serde_json::to_value(&config)?;
        assert!(json_val.get("scope").is_none());
        Ok(())
    }
}
