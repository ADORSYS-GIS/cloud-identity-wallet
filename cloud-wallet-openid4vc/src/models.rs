use time::OffsetDateTime;
use uuid::Uuid;

use crate::errors::{Error, ErrorKind};

/// Structural self-validation that a type can perform without external context.
pub trait Validatable {
    type Error;
    fn validate(&self) -> Result<(), Self::Error>;
}

/// Unique identifier for a [`Credential`] stored in the wallet.
///
/// Wraps a UUID string. All instances are guaranteed to carry a valid UUIDv4
/// at construction time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialId(String);

impl CredentialId {
    /// Generates a new random UUIDv4-based credential identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for CredentialId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for CredentialId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl CredentialId {
    /// Returns the underlying string as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<String> for CredentialId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Validate it's a valid UUID
        Uuid::parse_str(&value)
            .map(|_| Self(value))
            .map_err(|e| format!("invalid credential ID: {e}"))
    }
}

/// The type URI of a credential, as declared by the issuer.
///
/// For SD-JWT VCs this corresponds to the `vct` claim.
/// For W3C VC JWTs this corresponds to the `type` array in the credential body.
/// For mdoc this corresponds to the `docType` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialType(String);

impl CredentialType {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for CredentialType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The normalized, format-agnostic claim set of a credential.
///
/// Claims are extracted from the original encoded form at ingestion time and
/// stored as a flat JSON object, independent of format. For SD-JWT VCs this is
/// the decoded payload; for W3C VC JWTs this is the `credentialSubject`; for
/// mdoc this is a flat merge of all namespace claim maps.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Claims(serde_json::Value);

impl Claims {
    /// Constructs a [`Claims`] object from a JSON value.
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Returns the underlying JSON value.
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Retrieves a claim by key, returning `None` if the key is absent.
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }
}

impl From<serde_json::Value> for Claims {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}

impl std::ops::Index<&str> for Claims {
    type Output = serde_json::Value;

    fn index(&self, key: &str) -> &Self::Output {
        &self.0[key]
    }
}

/// A pointer to an issuer-maintained status list entry for this credential.
///
/// Modelled on the Token Status List draft (draft-ietf-oauth-status-list).
/// The wallet uses this reference to poll or resolve the current status of the
/// credential from the issuer's infrastructure.
///
/// Distinct from [`CredentialStatus`], which is the wallet's *derived*
/// view of the credential's usability after resolving the reference.
#[derive(Debug, Clone)]
pub struct StatusReference {
    /// The URL of the issuer's status list.
    pub status_list_url: String,

    /// The index of this credential within the status list.
    pub index: u64,
}

/// Holder key binding information for a credential.
#[derive(Debug, Clone)]
pub struct Binding;

/// Wallet-local metadata about a stored credential.
#[derive(Debug, Clone)]
pub struct CredentialMetadata {}

/// The wallet's local lifecycle view of a stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential is valid and usable.
    Active,
    /// The credential has been permanently revoked by the issuer.
    Revoked,
    /// The credential has been temporarily suspended by the issuer.
    Suspended,
}

/// The wallet's canonical, encoding-agnostic record for a stored credential.
///
/// This is the single source of truth for all credentials held in the wallet.
/// It is not a wire format and does not correspond directly to any object
/// defined by OpenID4VCI. Credentials are decoded from their original format
/// into this representation at ingestion time, stored as such, and re-encoded
/// via a [`CredentialFormat`] adapter when a presentation is needed.
///
/// [`CredentialFormat`]: crate::format::CredentialFormat
#[derive(Debug, Clone)]
pub struct Credential {
    /// Wallet-assigned unique identifier.
    pub id: CredentialId,

    /// The credential issuer's identifier (typically a URI or DID).
    pub issuer: String,

    /// The credential subject's identifier.
    pub subject: String,

    /// The type identifier declared by the issuer (e.g. `vct`, `docType`).
    pub credential_type: CredentialType,

    /// Normalized claims extracted from the credential at ingestion time.
    pub claims: Claims,

    /// When the credential was issued.
    pub issued_at: OffsetDateTime,

    /// When the credential expires, if applicable.
    pub expires_at: Option<OffsetDateTime>,

    /// Issuer-provided pointer to a status list entry, if present.
    ///
    /// `None` for credentials that carry no status list reference.
    pub status_reference: Option<StatusReference>,

    /// Holder key binding information.
    ///
    /// Use `Binding` for bearer credentials.
    pub binding: Binding,

    /// Wallet-local metadata needed for management and re-encoding.
    pub metadata: CredentialMetadata,

    /// The wallet's current lifecycle view of this credential.
    pub status: CredentialStatus,
}

impl Credential {
    /// Creates a new [`Credential`], validating structural invariants immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
        credential_type: CredentialType,
        claims: Claims,
        issued_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
        status_reference: Option<StatusReference>,
        binding: Binding,
        metadata: CredentialMetadata,
    ) -> Result<Self, Error> {
        let credential = Self {
            id: CredentialId::new(),
            issuer: issuer.into(),
            subject: subject.into(),
            credential_type,
            claims,
            issued_at,
            expires_at,
            status_reference,
            binding,
            metadata,
            status: CredentialStatus::Active,
        };
        credential.validate_structure()?;
        Ok(credential)
    }

    /// Validates structural invariants that require no external context.
    pub fn validate_structure(&self) -> Result<(), Error> {
        if self.issuer.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredential,
                "issuer must not be empty",
            ));
        }
        if self.subject.trim().is_empty() {
            return Err(Error::message(
                ErrorKind::InvalidCredential,
                "subject must not be empty",
            ));
        }
        if let Some(expires) = self.expires_at
            && expires <= self.issued_at
        {
            return Err(Error::message(
                ErrorKind::InvalidCredential,
                format!(
                    "expires_at ({expires}) must be strictly after issued_at ({})",
                    self.issued_at
                ),
            ));
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

    /// Marks this credential as revoked in the wallet's local record.
    ///
    /// Revocation is initiated by the issuer (e.g. via a status list update).
    /// This method reflects that status in the wallet's internal model.
    /// Revocation is terminal and cannot be undone.
    pub fn revoke(&mut self) {
        self.status = CredentialStatus::Revoked;
    }

    /// Marks this credential as suspended in the wallet's local record.
    ///
    /// Suspension is initiated by the issuer (e.g. via a status list update).
    /// This method reflects that status in the wallet's internal model.
    /// Returns an error with [`ErrorKind::CredentialRevoked`] if the credential
    /// is already revoked, since revocation is terminal and cannot be superseded.
    /// Calling this on an already-suspended credential is a no-op.
    pub fn suspend(&mut self) -> Result<(), Error> {
        match self.status {
            CredentialStatus::Revoked => Err(ErrorKind::CredentialRevoked.into()),
            CredentialStatus::Active | CredentialStatus::Suspended => {
                self.status = CredentialStatus::Suspended;
                Ok(())
            }
        }
    }

    /// Reactivates a suspended or active credential.
    ///
    /// Returns an error with [`ErrorKind::CredentialRevoked`] if the credential
    /// is revoked, since revocation is terminal.
    /// Calling this on an already-active credential is a no-op.
    pub fn reactivate(&mut self) -> Result<(), Error> {
        match self.status {
            CredentialStatus::Revoked => Err(ErrorKind::CredentialRevoked.into()),
            CredentialStatus::Active | CredentialStatus::Suspended => {
                self.status = CredentialStatus::Active;
                Ok(())
            }
        }
    }
}

impl Validatable for Credential {
    type Error = Error;

    fn validate(&self) -> Result<(), Self::Error> {
        self.validate_structure()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use time::Duration;

    fn metadata() -> CredentialMetadata {
        CredentialMetadata {}
    }

    fn sd_jwt_credential() -> Result<Credential, Error> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("https://credentials.example.com/identity"),
            Claims::new(json!({ "given_name": "Alice", "family_name": "Smith" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            metadata(),
        )
    }

    fn w3c_credential() -> Result<Credential, Error> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("UniversityDegreeCredential"),
            Claims::new(json!({ "degree": "BSc", "institution": "Example Uni" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            metadata(),
        )
    }

    fn mdoc_credential() -> Result<Credential, Error> {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("org.iso.18013.5.1.mDL"),
            Claims::new(json!({ "family_name": "Smith", "given_name": "John" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            metadata(),
        )
    }

    // Construction

    #[test]
    fn credential_created_with_active_status() -> Result<(), Error> {
        let cred = sd_jwt_credential()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn credential_id_is_valid_uuid() -> Result<(), Error> {
        let cred = sd_jwt_credential()?;
        assert!(uuid::Uuid::parse_str(cred.id.as_ref()).is_ok());
        Ok(())
    }

    #[test]
    fn credential_rejects_blank_issuer() {
        let err = Credential::new(
            "  ",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc(),
            None,
            None,
            Binding,
            metadata(),
        )
        .expect_err("expected an error for a blank issuer");

        assert!(
            err.kind() == ErrorKind::InvalidCredential && err.to_string().contains("issuer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_rejects_blank_subject() {
        let err = Credential::new(
            "https://issuer.example.com",
            "",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc(),
            None,
            None,
            Binding,
            metadata(),
        )
        .expect_err("expected an error for a blank subject");

        assert!(
            err.kind() == ErrorKind::InvalidCredential && err.to_string().contains("subject"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_rejects_expiry_before_issuance() {
        let now = OffsetDateTime::now_utc();
        let err = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            now,
            Some(now - Duration::seconds(1)),
            None,
            Binding,
            metadata(),
        )
        .expect_err("expected an error when expires_at is before issued_at");

        assert!(
            err.kind() == ErrorKind::InvalidCredential && err.to_string().contains("expires_at"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn credential_without_expiry_is_valid() {
        assert!(
            Credential::new(
                "https://issuer.example.com",
                "user-1234",
                CredentialType::new("vct"),
                Claims::new(json!({})),
                OffsetDateTime::now_utc(),
                None,
                None,
                Binding,
                metadata(),
            )
            .is_ok()
        );
    }

    // Status transitions

    #[test]
    fn revoke_is_idempotent() -> Result<(), Error> {
        let mut cred = sd_jwt_credential()?;
        cred.revoke();
        assert_eq!(cred.status, CredentialStatus::Revoked);
        cred.revoke();
        assert_eq!(cred.status, CredentialStatus::Revoked);
        Ok(())
    }

    #[test]
    fn cannot_suspend_revoked() -> Result<(), Error> {
        let mut cred = sd_jwt_credential()?;
        cred.revoke();
        let err = cred
            .suspend()
            .expect_err("expected an error suspending a revoked credential");
        assert!(
            err.kind() == ErrorKind::CredentialRevoked,
            "unexpected error variant: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn suspend_and_reactivate() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = sd_jwt_credential()?;
        cred.suspend()?;
        assert_eq!(cred.status, CredentialStatus::Suspended);
        cred.reactivate()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn reactivate_already_active_is_no_op() -> Result<(), Box<dyn std::error::Error>> {
        let mut cred = sd_jwt_credential()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        cred.reactivate()?;
        assert_eq!(cred.status, CredentialStatus::Active);
        Ok(())
    }

    #[test]
    fn cannot_reactivate_revoked() -> Result<(), Error> {
        let mut cred = sd_jwt_credential()?;
        cred.revoke();
        let err = cred
            .reactivate()
            .expect_err("expected an error reactivating a revoked credential");
        assert!(
            err.kind() == ErrorKind::CredentialRevoked,
            "unexpected error variant: {err}"
        );
        Ok(())
    }

    // All three credential types construct correctly

    #[test]
    fn all_three_types_construct() -> Result<(), Error> {
        assert!(sd_jwt_credential()?.is_usable());
        assert!(w3c_credential()?.is_usable());
        assert!(mdoc_credential()?.is_usable());
        Ok(())
    }

    // Claims

    #[test]
    fn claims_accessible_by_key() -> Result<(), Error> {
        let cred = sd_jwt_credential()?;
        assert_eq!(cred.claims["given_name"], "Alice");
        assert_eq!(cred.claims["family_name"], "Smith");
        Ok(())
    }

    #[test]
    fn claims_get_returns_none_for_absent_key() -> Result<(), Error> {
        let cred = sd_jwt_credential()?;
        assert!(cred.claims.get("nonexistent").is_none());
        Ok(())
    }

    #[test]
    fn claims_from_json_value() {
        let value = json!({ "sub": "user-1" });
        let claims = Claims::from(value.clone());
        assert_eq!(claims.as_value(), &value);
    }

    // Status reference

    #[test]
    fn status_reference_is_stored() -> Result<(), Error> {
        let cred = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc(),
            None,
            Some(StatusReference {
                status_list_url: "https://issuer.example.com/status/1".to_owned(),
                index: 42,
            }),
            Binding,
            metadata(),
        )?;
        let sr = cred
            .status_reference
            .as_ref()
            .expect("status reference should be present");
        assert_eq!(sr.index, 42);
        Ok(())
    }

    // Expiry

    #[test]
    fn expired_credential_is_not_usable() -> Result<(), Error> {
        let mut cred = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc() - Duration::days(10),
            Some(OffsetDateTime::now_utc() - Duration::days(1)),
            None,
            Binding,
            metadata(),
        )?;
        cred.status = CredentialStatus::Active;
        assert!(cred.is_expired());
        assert!(!cred.is_usable());
        Ok(())
    }

    #[test]
    fn credential_without_expiry_never_expires() -> Result<(), Error> {
        let cred = Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("vct"),
            Claims::new(json!({})),
            OffsetDateTime::now_utc(),
            None,
            None,
            Binding,
            metadata(),
        )?;
        assert!(!cred.is_expired());
        assert!(cred.is_usable());
        Ok(())
    }

    // Validatable

    #[test]
    fn validate_passes_for_valid_credential() -> Result<(), Box<dyn std::error::Error>> {
        let cred = sd_jwt_credential()?;
        assert!(cred.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_catches_blank_issuer() {
        let cred = Credential {
            id: CredentialId::new(),
            issuer: "  ".to_owned(),
            subject: "user-1234".to_owned(),
            credential_type: CredentialType::new("vct"),
            claims: Claims::new(json!({})),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: None,
            status_reference: None,
            binding: Binding,
            metadata: metadata(),
            status: CredentialStatus::Active,
        };
        assert!(cred.validate().is_err());
    }
}
