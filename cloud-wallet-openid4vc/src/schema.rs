use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
