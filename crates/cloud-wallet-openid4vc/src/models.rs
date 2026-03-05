use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::errors::{CredentialError, ValidationError};
use crate::schema::CredentialFormatIdentifier;
use crate::validation::Validatable;

/// Unique identifier for a [`Credential`] stored in the wallet.
///
/// Represented as a UUID string for broad compatibility with storage backends
/// and external systems that may not natively handle UUID types.
pub type CredentialId = String;

/// Generates a new random [`CredentialId`].
pub fn new_credential_id() -> CredentialId {
    Uuid::new_v4().to_string()
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
    /// Returns the claims for the given namespace, or `None` if the namespace
    /// is not present in this credential.
    pub fn claims(&self, namespace: &str) -> Option<&serde_json::Value> {
        self.namespaces.get(namespace)
    }
}

/// The full credential token and its format-specific payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum CredentialPayload {
    /// SD-JWT VC — tag value `"dc+sd-jwt"`.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt(SdJwtCredential),

    /// ISO mdoc — tag value `"mso_mdoc"`.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(MsoMdocCredential),

    /// W3C VC JWT — tag value `"jwt_vc_json"`.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(W3cVcJwtCredential),
}

impl CredentialPayload {
    /// Returns the [`CredentialFormatIdentifier`] for this credential payload.
    pub fn format_identifier(&self) -> CredentialFormatIdentifier {
        match self {
            CredentialPayload::DcSdJwt(_) => CredentialFormatIdentifier::DcSdJwt,
            CredentialPayload::MsoMdoc(_) => CredentialFormatIdentifier::MsoMdoc,
            CredentialPayload::JwtVcJson(_) => CredentialFormatIdentifier::JwtVcJson,
        }
    }

    /// Returns the claims for SD-JWT and W3C VC formats.
    /// For mdoc, use [`MsoMdocCredential::claims`] with an explicit namespace instead.
    pub fn claims(&self) -> Option<&serde_json::Value> {
        match self {
            CredentialPayload::DcSdJwt(c) => Some(&c.claims),
            CredentialPayload::JwtVcJson(c) => Some(&c.credential_subject),
            CredentialPayload::MsoMdoc(_) => None,
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

    /// The full credential token and its format-specific payload.
    pub credential: CredentialPayload,

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
        credential: CredentialPayload,
    ) -> Result<Self, ValidationError> {
        let credential = Self {
            id: new_credential_id(),
            issuer: issuer.into(),
            subject: subject.into(),
            issued_at,
            expires_at,
            credential_configuration_id: credential_configuration_id.into(),
            credential,
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

    /// Revokes this credential.
    pub fn revoke(&mut self) {
        self.status = CredentialStatus::Revoked;
    }

    /// Suspends this credential.
    pub fn suspend(&mut self) -> Result<(), CredentialError> {
        match self.status {
            CredentialStatus::Revoked => Err(CredentialError::Revoked),
            CredentialStatus::Active | CredentialStatus::Suspended => {
                self.status = CredentialStatus::Suspended;
                Ok(())
            }
        }
    }

    /// Reactivates a suspended or active credential.
    pub fn reactivate(&mut self) -> Result<(), CredentialError> {
        match self.status {
            CredentialStatus::Revoked => Err(CredentialError::Revoked),
            CredentialStatus::Active | CredentialStatus::Suspended => {
                self.status = CredentialStatus::Active;
                Ok(())
            }
        }
    }
}

impl Validatable for Credential {
    type Error = ValidationError;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_structure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::Duration;

    fn sd_jwt_payload() -> CredentialPayload {
        CredentialPayload::DcSdJwt(SdJwtCredential {
            token: "header.payload.sig~disclosure~".to_owned(),
            vct: "https://credentials.example.com/identity_credential".to_owned(),
            claims: json!({ "given_name": "Alice", "family_name": "Smith" }),
        })
    }

    fn w3c_payload() -> CredentialPayload {
        CredentialPayload::JwtVcJson(W3cVcJwtCredential {
            token: "header.payload.sig".to_owned(),
            credential_type: vec![
                "VerifiableCredential".to_owned(),
                "UniversityDegreeCredential".to_owned(),
            ],
            credential_subject: json!({ "degree": "BSc", "institution": "Example Uni" }),
        })
    }

    fn mdoc_payload() -> CredentialPayload {
        let mut ns = std::collections::HashMap::new();
        ns.insert(
            "org.iso.18013.5.1".to_owned(),
            json!({ "family_name": "Smith", "given_name": "John" }),
        );
        CredentialPayload::MsoMdoc(MsoMdocCredential {
            doc_type: "org.iso.18013.5.1.mDL".to_owned(),
            namespaces: ns,
            issuer_signed: "base64url-mso".to_owned(),
        })
    }

    fn valid_credential(credential: CredentialPayload) -> Result<Credential, ValidationError> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            credential,
        )
    }

    // Construction

    #[test]
    fn credential_created_with_active_status() -> Result<(), ValidationError> {
        let cred = valid_credential(sd_jwt_payload())?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn credential_id_is_non_empty_uuid_string() -> Result<(), ValidationError> {
        let cred = valid_credential(sd_jwt_payload())?;
        assert!(uuid::Uuid::parse_str(&cred.id).is_ok());
        Ok(())
    }

    #[test]
    fn credential_rejects_blank_issuer() {
        let err = Credential::new(
            "  ",
            "user-1234",
            OffsetDateTime::now_utc(),
            None,
            "cfg_id",
            sd_jwt_payload(),
        )
        .expect_err("expected an error for a blank issuer");

        assert!(
            matches!(&err, ValidationError::InvalidCredential { reason } if reason.contains("issuer")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_rejects_blank_subject() {
        let err = Credential::new(
            "https://issuer.example.com",
            "",
            OffsetDateTime::now_utc(),
            None,
            "cfg_id",
            sd_jwt_payload(),
        )
        .expect_err("expected an error for a blank subject");

        assert!(
            matches!(&err, ValidationError::InvalidCredential { reason } if reason.contains("subject")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_rejects_expiry_before_issuance() {
        let now = OffsetDateTime::now_utc();
        let err = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            now,
            Some(now - Duration::seconds(1)),
            "cfg_id",
            sd_jwt_payload(),
        )
        .expect_err("expected an error when expires_at is before issued_at");

        assert!(
            matches!(&err, ValidationError::InvalidCredential { reason } if reason.contains("expires_at")),
            "unexpected error: {err}"
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
                sd_jwt_payload()
            )
            .is_ok()
        );
    }

    // Status transitions
    #[test]
    fn revoke_is_idempotent() -> Result<(), ValidationError> {
        let mut cred = valid_credential(sd_jwt_payload())?;
        cred.revoke();
        assert_eq!(cred.status, CredentialStatus::Revoked);
        cred.revoke();
        assert_eq!(cred.status, CredentialStatus::Revoked);
        Ok(())
    }

    #[test]
    fn cannot_suspend_revoked() -> Result<(), ValidationError> {
        let mut cred = valid_credential(sd_jwt_payload())?;
        cred.revoke();
        let err = cred
            .suspend()
            .expect_err("expected an error suspending a revoked credential");
        assert!(
            matches!(err, CredentialError::Revoked),
            "unexpected error variant: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn suspend_and_reactivate() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = valid_credential(sd_jwt_payload())?;
        cred.suspend()?;
        assert_eq!(cred.status, CredentialStatus::Suspended);
        cred.reactivate()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn reactivate_already_active_is_no_op() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = valid_credential(sd_jwt_payload())?;
        assert_eq!(cred.status, CredentialStatus::Active);
        cred.reactivate()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn cannot_reactivate_revoked() -> Result<(), ValidationError> {
        let mut cred = valid_credential(sd_jwt_payload())?;
        cred.revoke();
        let err = cred
            .reactivate()
            .expect_err("expected an error reactivating a revoked credential");
        assert!(
            matches!(err, CredentialError::Revoked),
            "unexpected error variant: {err}"
        );
        Ok(())
    }

    // Format identifier wire values
    #[test]
    fn format_identifiers_match_spec_wire_values() {
        assert_eq!(
            sd_jwt_payload().format_identifier(),
            CredentialFormatIdentifier::DcSdJwt
        );
        assert_eq!(
            w3c_payload().format_identifier(),
            CredentialFormatIdentifier::JwtVcJson
        );
        assert_eq!(
            mdoc_payload().format_identifier(),
            CredentialFormatIdentifier::MsoMdoc
        );
    }

    // All three formats construct and serialize

    #[test]
    fn all_three_formats_construct() -> Result<(), ValidationError> {
        assert!(valid_credential(sd_jwt_payload())?.is_usable());
        assert!(valid_credential(w3c_payload())?.is_usable());
        assert!(valid_credential(mdoc_payload())?.is_usable());
        Ok(())
    }

    #[test]
    fn credential_round_trips_through_json() -> Result<(), Box<dyn std::error::Error>> {
        let cred = valid_credential(sd_jwt_payload())?;
        let json = serde_json::to_string(&cred)?;
        let restored: Credential = serde_json::from_str(&json)?;
        assert_eq!(restored.id, cred.id);
        assert_eq!(
            restored.credential.format_identifier(),
            CredentialFormatIdentifier::DcSdJwt
        );
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
            sd_jwt_payload(),
        )?;
        cred.status = CredentialStatus::Active;
        assert!(cred.is_expired());
        assert!(!cred.is_usable());
        Ok(())
    }

    // claims() accessor

    #[test]
    fn sd_jwt_claims_accessible() {
        let payload = sd_jwt_payload();
        let claims = payload
            .claims()
            .expect("SD-JWT payload should return Some claims");
        assert_eq!(claims["given_name"], "Alice");
    }

    #[test]
    fn w3c_claims_accessible() {
        let payload = w3c_payload();
        let claims = payload
            .claims()
            .expect("W3C VC payload should return Some claims");
        assert_eq!(claims["degree"], "BSc");
    }

    #[test]
    fn mdoc_claims_returns_none_from_payload() {
        // claims() on mdoc is intentionally None — use mdoc.claims(namespace) instead
        assert!(mdoc_payload().claims().is_none());
    }

    #[test]
    fn mdoc_claims_for_namespace_returns_correct_namespace() {
        if let CredentialPayload::MsoMdoc(mdoc) = mdoc_payload() {
            let claims = mdoc
                .claims("org.iso.18013.5.1")
                .expect("namespace should be present");
            assert_eq!(claims["family_name"], "Smith");
            assert!(mdoc.claims("org.iso.18013.5.1.aamva").is_none());
        }
    }
}
