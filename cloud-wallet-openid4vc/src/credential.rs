pub mod tenants;

use core::str::FromStr;

use serde_json::Value;
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialStatus {
    Active,
    Revoked,
    Expired,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialFormat {
    SdJwtVc,
    Mdoc,
    JwtVcJson,
    JwtVcJsonLd,
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

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Uuid,
    pub tenant_id: Uuid,

    pub issuer: String,
    pub subject: Option<String>,

    pub credential_types: Value,
    pub format: CredentialFormat,
    pub external_id: Option<String>,

    pub status: CredentialStatus,
    pub issued_at: UtcDateTime,
    pub valid_until: Option<UtcDateTime>,

    pub is_revoked: bool,
    pub status_location: Option<Url>,
    pub status_index: Option<i64>,

    pub raw_credential: Box<[u8]>,
}
