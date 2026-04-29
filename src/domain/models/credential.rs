use core::str::FromStr;

use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

type DynError = Box<dyn std::error::Error + Send + Sync>;

/// Errors that can occur during credential storage operations.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("Storage backend error: {0}")]
    Backend(DynError),

    #[error("Credential not found for id={id}, tenant_id={tenant_id}")]
    NotFound { id: Uuid, tenant_id: Uuid },

    #[error("Invalid stored credential data: {0}")]
    InvalidData(String),

    #[error("Encryption or decryption error: {0}")]
    Encryption(DynError),

    #[error("Storage error: {0}")]
    Other(String),
}

/// Lifecycle status of an issued credential.
///
/// Represents the current state of a credential in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialStatus {
    /// The credential is valid and active.
    Active,
    /// The credential has been permanently revoked.
    Revoked,
    /// The credential's validity period has expired.
    Expired,
    /// The credential is temporarily suspended.
    Suspended,
}

impl CredentialStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Suspended => "suspended",
        }
    }
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CredentialStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            "suspended" => Ok(Self::Suspended),
            _ => Err("invalid credential status"),
        }
    }
}

/// Wire format used for the credential payload.
///
/// Specifies the standard format used to encode the credential data.
/// Examples include `dc+sd-jwt` and `mso_mdoc`. Note that string parsing
/// behaves differently than default debug formatting (e.g., `FromStr` uses standard
/// OpenID4VCI format identifiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialFormat {
    /// SD-JWT based Verifiable Credential (`dc+sd-jwt`)
    SdJwtVc,
    /// ISO 18013-5 mdoc (`mso_mdoc`)
    Mdoc,
    /// JWT based Verifiable Credential (`jwt_vc_json`)
    JwtVcJson,
    /// JWT based Verifiable Credential with JSON-LD (`jwt_vc_json-ld`)
    JwtVcJsonLd,
    /// Linked Data Proof Verifiable Credential (`ldp_vc`)
    LdpVc,
}

impl CredentialFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SdJwtVc => "dc+sd-jwt",
            Self::Mdoc => "mso_mdoc",
            Self::JwtVcJson => "jwt_vc_json",
            Self::JwtVcJsonLd => "jwt_vc_json-ld",
            Self::LdpVc => "ldp_vc",
        }
    }
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CredentialFormat {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dc+sd-jwt" => Ok(Self::SdJwtVc),
            "mso_mdoc" => Ok(Self::Mdoc),
            "jwt_vc_json" => Ok(Self::JwtVcJson),
            "jwt_vc_json-ld" => Ok(Self::JwtVcJsonLd),
            "ldp_vc" => Ok(Self::LdpVc),
            _ => Err("invalid credential format"),
        }
    }
}

/// Represents a Verifiable Credential.
///
/// Contains both the raw credential data and parsed metadata useful for
/// querying, displaying, and managing the lifecycle of the credential.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Unique identifier for this credential.
    pub id: Uuid,
    /// Identifier of the tenant that owns this credential.
    pub tenant_id: Uuid,

    /// The entity that issued the credential (e.g., a DID or URL).
    pub issuer: String,
    /// The subject of the credential (e.g., a DID).
    pub subject: Option<String>,

    /// The type(s) associated with this credential.
    pub credential_types: Vec<String>,
    /// The wire format of the credential payload.
    pub format: CredentialFormat,
    /// An optional external identifier provided by the issuer.
    pub external_id: Option<String>,

    /// The current lifecycle status of the credential.
    pub status: CredentialStatus,
    /// The date and time when the credential was issued.
    pub issued_at: UtcDateTime,
    /// The date and time when the credential expires, if any.
    pub valid_until: Option<UtcDateTime>,

    /// Whether the credential has been marked as revoked.
    pub is_revoked: bool,
    /// The URL where the credential status can be checked.
    pub status_location: Option<Url>,
    /// The index of this credential in the status list, if applicable.
    pub status_index: Option<i64>,

    /// The actual serialized credential string (e.g., the SD-JWT or base64 mdoc).
    pub raw_credential: String,
}

/// Filter criteria for listing credentials.
#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    pub tenant_id: Option<Uuid>,
    pub credential_types: Option<Vec<String>>,
    pub status: Option<CredentialStatus>,
    pub format: Option<CredentialFormat>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub exclude_expired: bool,
}

impl CredentialFilter {
    /// Checks if a credential matches the filter criteria.
    pub fn matches(&self, credential: &Credential) -> bool {
        if let Some(tenant_id) = self.tenant_id
            && credential.tenant_id != tenant_id
        {
            return false;
        }
        if let Some(status) = self.status
            && credential.status != status
        {
            return false;
        }
        if let Some(format) = self.format
            && credential.format != format
        {
            return false;
        }
        if let Some(issuer) = &self.issuer
            && credential.issuer != *issuer
        {
            return false;
        }
        if let Some(subject) = &self.subject
            && credential.subject.as_deref() != Some(subject.as_str())
        {
            return false;
        }
        if let Some(types) = &self.credential_types
            && !types.iter().any(|t| credential.credential_types.contains(t))
        {
            return false;
        }
        if self.exclude_expired
            && let Some(valid_until) = credential.valid_until
            && valid_until <= time::UtcDateTime::now()
        {
            return false;
        }
        true
    }
}
