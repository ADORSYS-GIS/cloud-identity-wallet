use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::errors::{CredentialError, ValidationError};

/// Opaque, unique identifier for a [`Credential`] stored in the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(Uuid);

impl CredentialId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle status of a stored [`Credential`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Revoked,
    Suspended,
}

// Format-specific payload types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtCredential {
    pub token: String,

    pub vct: String,

    pub claims: serde_json::Value,
}

/// Payload for a stored W3C VC JWT credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcJwtCredential {
    pub token: String,

    #[serde(rename = "type")]
    pub credential_type: Vec<String>,

    /// The `credentialSubject` claims.
    pub credential_subject: serde_json::Value,
}

/// Payload for a stored ISO mdoc credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocCredential {
    pub doc_type: String,

    pub namespaces: std::collections::HashMap<String, serde_json::Value>,

    /// The issuer-signed MSO, base64url-encoded.
    pub issuer_signed: String,
}

impl MsoMdocCredential {
    pub fn claims_for_namespace(&self, namespace: &str) -> Option<&serde_json::Value> {
        self.namespaces.get(namespace)
    }
}

/// The format-specific payload of a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum CredentialFormat {
    /// SD-JWT VC — tag value `"vc+sd-jwt"`.
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt(SdJwtCredential),

    /// ISO mdoc — tag value `"mso_mdoc"`.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(MsoMdocCredential),

    /// W3C VC JWT — tag value `"jwt_vc_json"`.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(W3cVcJwtCredential),
}

impl CredentialFormat {
    /// Returns the spec-defined format identifier string for this credential.
    pub fn format_identifier(&self) -> &'static str {
        match self {
            CredentialFormat::VcSdJwt(_) => "vc+sd-jwt",
            CredentialFormat::MsoMdoc(_) => "mso_mdoc",
            CredentialFormat::JwtVcJson(_) => "jwt_vc_json",
        }
    }

    /// Returns the claims for SD-JWT and W3C VC formats.
    /// [`MsoMdocCredential::claims_for_namespace`]
    pub fn claims(&self) -> Option<&serde_json::Value> {
        match self {
            CredentialFormat::VcSdJwt(c) => Some(&c.claims),
            CredentialFormat::JwtVcJson(c) => Some(&c.credential_subject),
            CredentialFormat::MsoMdoc(_) => None,
        }
    }
}

/// A verifiable credential stored in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: CredentialId,

    pub issuer: String,

    pub subject: String,

    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub expires_at: Option<OffsetDateTime>,

    pub credential_configuration_id: String,

    pub format: CredentialFormat,

    pub status: CredentialStatus,
}

impl Credential {
    /// Creates a new [`Credential`], validating structural invariants immediately.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        issued_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
        credential_configuration_id: impl Into<String>,
        format: CredentialFormat,
    ) -> Result<Self, ValidationError> {
        let credential = Self {
            id: CredentialId::new(),
            issuer: issuer.into(),
            subject: subject.into(),
            issued_at,
            expires_at,
            credential_configuration_id: credential_configuration_id.into(),
            format,
            status: CredentialStatus::Active,
        };
        credential.validate_structure()?;
        Ok(credential)
    }

    /// Validates structural invariants that require no external context.
    pub fn validate_structure(&self) -> Result<(), ValidationError> {
        if self.issuer.trim().is_empty() {
            return Err(ValidationError::InvalidCredential {
                reason: "issuer must not be empty".to_owned(),
            });
        }
        if self.subject.trim().is_empty() {
            return Err(ValidationError::InvalidCredential {
                reason: "subject must not be empty".to_owned(),
            });
        }
        if let Some(expires) = self.expires_at
            && expires <= self.issued_at
        {
            return Err(ValidationError::InvalidCredential {
                reason: format!(
                    "expires_at ({expires}) must be strictly after issued_at ({})",
                    self.issued_at
                ),
            });
        }
        Ok(())
    }

    /// Returns `true` if the credential is active and has not expired.
    pub fn is_usable(&self) -> bool {
        self.status == CredentialStatus::Active && !self.is_expired()
    }

    /// Returns `true` if the credential has passed its `expires_at` timestamp.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| exp <= OffsetDateTime::now_utc())
            .unwrap_or(false)
    }

    /// Revokes this credential. Revocation is terminal.
    pub fn revoke(&mut self) -> Result<(), CredentialError> {
        if self.status == CredentialStatus::Revoked {
            return Err(CredentialError::Revoked);
        }
        self.status = CredentialStatus::Revoked;
        Ok(())
    }

    /// Suspends this credential.
    pub fn suspend(&mut self) -> Result<(), CredentialError> {
        if self.status == CredentialStatus::Revoked {
            return Err(CredentialError::Revoked);
        }
        self.status = CredentialStatus::Suspended;
        Ok(())
    }

    /// Reactivates a suspended credential.
    pub fn reactivate(&mut self) -> Result<(), CredentialError> {
        match self.status {
            CredentialStatus::Revoked => Err(CredentialError::Revoked),
            CredentialStatus::Active => Err(CredentialError::AlreadyActive),
            CredentialStatus::Suspended => {
                self.status = CredentialStatus::Active;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::Duration;

    fn sd_jwt_format() -> CredentialFormat {
        CredentialFormat::VcSdJwt(SdJwtCredential {
            token: "header.payload.sig~disclosure~".to_owned(),
            vct: "https://credentials.example.com/identity_credential".to_owned(),
            claims: json!({ "given_name": "Alice", "family_name": "Smith" }),
        })
    }

    fn w3c_format() -> CredentialFormat {
        CredentialFormat::JwtVcJson(W3cVcJwtCredential {
            token: "header.payload.sig".to_owned(),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                "UniversityDegreeCredential".to_owned(),
            ],
            credential_subject: json!({ "degree": "BSc", "institution": "Example Uni" }),
        })
    }

    fn mdoc_format() -> CredentialFormat {
        let mut ns = std::collections::HashMap::new();
        ns.insert(
            "org.iso.18013.5.1".to_owned(),
            json!({ "family_name": "Smith", "given_name": "John" }),
        );
        CredentialFormat::MsoMdoc(MsoMdocCredential {
            doc_type: "org.iso.18013.5.1.mDL".to_owned(),
            namespaces: ns,
            issuer_signed: "base64url-mso".to_owned(),
        })
    }

    fn valid_credential(format: CredentialFormat) -> Result<Credential, ValidationError> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            format,
        )
    }

    // Construction

    #[test]
    fn credential_created_with_active_status() -> Result<(), ValidationError> {
        let cred = valid_credential(sd_jwt_format())?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn credential_rejects_blank_issuer() {
        assert!(
            Credential::new(
                "  ",
                "user-1234",
                OffsetDateTime::now_utc(),
                None,
                "cfg_id",
                sd_jwt_format()
            )
            .is_err()
        );
    }

    #[test]
    fn credential_rejects_blank_subject() {
        assert!(
            Credential::new(
                "https://issuer.example.com",
                "",
                OffsetDateTime::now_utc(),
                None,
                "cfg_id",
                sd_jwt_format()
            )
            .is_err()
        );
    }

    #[test]
    fn credential_rejects_expiry_before_issuance() {
        let now = OffsetDateTime::now_utc();
        assert!(
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                now,
                Some(now - Duration::seconds(1)),
                "cfg_id",
                sd_jwt_format()
            )
            .is_err()
        );
    }

    #[test]
    fn credential_without_expiry_is_valid() {
        assert!(
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                OffsetDateTime::now_utc(),
                None,
                "cfg_id",
                sd_jwt_format()
            )
            .is_ok()
        );
    }

    // Status transitions

    #[test]
    fn revoke_succeeds_and_is_terminal() -> Result<(), ValidationError> {
        let mut cred = valid_credential(sd_jwt_format())?;
        assert!(cred.revoke().is_ok());
        assert_eq!(cred.status, CredentialStatus::Revoked);
        assert!(cred.revoke().is_err());
        Ok(())
    }

    #[test]
    fn suspend_and_reactivate() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = valid_credential(sd_jwt_format())?;
        cred.suspend()?;
        assert_eq!(cred.status, CredentialStatus::Suspended);
        cred.reactivate()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn cannot_reactivate_revoked() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = valid_credential(sd_jwt_format())?;
        cred.revoke()?;
        assert!(cred.reactivate().is_err());
        Ok(())
    }

    #[test]
    fn cannot_suspend_revoked() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = valid_credential(sd_jwt_format())?;
        cred.revoke()?;
        assert!(cred.suspend().is_err());
        Ok(())
    }

    #[test]
    fn reactivate_already_active_returns_error() -> Result<(), ValidationError> {
        let cred = valid_credential(sd_jwt_format())?;
        assert!(cred.clone().reactivate().is_err());
        Ok(())
    }

    // Format identifier wire values

    #[test]
    fn format_identifiers_match_spec_wire_values() {
        assert_eq!(sd_jwt_format().format_identifier(), "vc+sd-jwt");
        assert_eq!(w3c_format().format_identifier(), "jwt_vc_json");
        assert_eq!(mdoc_format().format_identifier(), "mso_mdoc");
    }

    // All three formats construct and serialize

    #[test]
    fn all_three_formats_construct() -> Result<(), ValidationError> {
        assert!(valid_credential(sd_jwt_format())?.is_usable());
        assert!(valid_credential(w3c_format())?.is_usable());
        assert!(valid_credential(mdoc_format())?.is_usable());
        Ok(())
    }

    #[test]
    fn credential_round_trips_through_json() -> Result<(), Box<dyn std::error::Error>> {
        let cred = valid_credential(sd_jwt_format())?;
        let json = serde_json::to_string(&cred)?;
        let restored: Credential = serde_json::from_str(&json)?;
        assert_eq!(restored.id, cred.id);
        assert_eq!(restored.format.format_identifier(), "vc+sd-jwt");
        Ok(())
    }

    // Expiry

    #[test]
    fn expired_credential_is_not_usable() -> Result<(), ValidationError> {
        let mut cred = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            OffsetDateTime::now_utc() - Duration::days(10),
            Some(OffsetDateTime::now_utc() - Duration::days(1)),
            "cfg_id",
            sd_jwt_format(),
        )?;
        cred.status = CredentialStatus::Active;
        assert!(cred.is_expired());
        assert!(!cred.is_usable());
        Ok(())
    }

    // claims() accessor

    #[test]
    fn sd_jwt_claims_accessible() {
        let format = sd_jwt_format();
        let claims = format
            .claims()
            .expect("SD-JWT format should return Some claims");
        assert_eq!(claims["given_name"], "Alice");
    }

    #[test]
    fn w3c_claims_accessible() {
        let format = w3c_format();
        let claims = format
            .claims()
            .expect("W3C VC format should return Some claims");
        assert_eq!(claims["degree"], "BSc");
    }

    #[test]
    fn mdoc_claims_returns_none_from_format() {
        // claims() on mdoc is intentionally None — use claims_for_namespace() instead
        let format = mdoc_format();
        assert!(format.claims().is_none());
    }

    #[test]
    fn mdoc_claims_for_namespace_returns_correct_namespace() {
        let format = mdoc_format();
        if let CredentialFormat::MsoMdoc(mdoc) = &format {
            let claims = mdoc
                .claims_for_namespace("org.iso.18013.5.1")
                .expect("namespace should be present");
            assert_eq!(claims["family_name"], "Smith");
            assert!(
                mdoc.claims_for_namespace("org.iso.18013.5.1.aamva")
                    .is_none()
            );
        }
    }
}
