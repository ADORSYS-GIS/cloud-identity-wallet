//! Core credential data model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Supported OpenID4VCI credential formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CredentialFormat {
    /// SD-JWT Verifiable Credential (`dc+sd-jwt`)
    DcSdJwt,
    /// ISO/IEC 18013-5 mobile driving licence / mdoc (`mso_mdoc`)
    MsoMdoc,
    /// W3C Verifiable Credentials Data Model as JWT (`jwt_vc_json`)
    JwtVcJson,
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DcSdJwt => "dc+sd-jwt",
            Self::MsoMdoc => "mso_mdoc",
            Self::JwtVcJson => "jwt_vc_json",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for CredentialFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dc+sd-jwt" => Ok(Self::DcSdJwt),
            "mso_mdoc" => Ok(Self::MsoMdoc),
            "jwt_vc_json" => Ok(Self::JwtVcJson),
            other => Err(format!("unknown credential format: {other}")),
        }
    }
}

/// Reference to a Status List entry for revocation checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// URL of the Status List credential.
    pub status_list_url: String,
    /// Index of this credential in the status list bit array.
    pub status_list_index: u64,
}

/// Searchable, non-sensitive credential metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub iss: String,
    pub iat: DateTime<Utc>,
    pub exp: Option<DateTime<Utc>>,
    pub sub: Option<String>,
    /// SD-JWT VC type string (`vct` claim). Only set for [`CredentialFormat::DcSdJwt`].
    pub vct: Option<String>,
    /// ISO mdoc document type (`doctype`). Only set for [`CredentialFormat::MsoMdoc`].
    pub doctype: Option<String>,
    /// W3C VCDM `@type` array. Only set for [`CredentialFormat::JwtVcJson`].
    pub credential_type: Option<Vec<String>>,
    pub credential_configuration_id: Option<String>,
    pub status: Option<CredentialStatus>,
}

/// A stored Verifiable Credential record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub format: CredentialFormat,
    pub raw_credential: String,
    pub metadata: CredentialMetadata,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    /// Create a new [`Credential`] with the current UTC timestamp.
    pub fn new(
        format: CredentialFormat,
        raw_credential: String,
        metadata: CredentialMetadata,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            format,
            raw_credential,
            metadata,
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns `true` if the credential has expired relative to `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.metadata.exp.is_some_and(|exp| now >= exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_credential_new() {
        let metadata = CredentialMetadata {
            iss: "https://issuer.example.com".to_string(),
            iat: Utc::now(),
            exp: None,
            sub: None,
            vct: None,
            doctype: None,
            credential_type: None,
            credential_configuration_id: None,
            status: None,
        };
        let cred = Credential::new(CredentialFormat::DcSdJwt, "raw".to_string(), metadata);

        assert_eq!(cred.format, CredentialFormat::DcSdJwt);
        assert_eq!(cred.raw_credential, "raw");
        assert_eq!(cred.created_at, cred.updated_at);
    }

    #[test]
    fn test_credential_expiry() {
        let now = Utc::now();
        let mut metadata = CredentialMetadata {
            iss: "iss".to_string(),
            iat: now,
            exp: Some(now + Duration::seconds(10)),
            sub: None,
            vct: None,
            doctype: None,
            credential_type: None,
            credential_configuration_id: None,
            status: None,
        };
        let cred = Credential::new(
            CredentialFormat::DcSdJwt,
            "raw".to_string(),
            metadata.clone(),
        );

        assert!(!cred.is_expired_at(now));
        assert!(cred.is_expired_at(now + Duration::seconds(10)));
        assert!(cred.is_expired_at(now + Duration::seconds(20)));

        metadata.exp = None;
        let cred_no_exp = Credential::new(CredentialFormat::DcSdJwt, "raw".to_string(), metadata);
        assert!(!cred_no_exp.is_expired_at(now + Duration::days(365)));
    }

    #[test]
    fn test_credential_serialization() {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let cred = Credential {
            id,
            format: CredentialFormat::DcSdJwt,
            raw_credential: "raw".to_string(),
            metadata: CredentialMetadata {
                iss: "iss".to_string(),
                iat: now,
                exp: None,
                sub: None,
                vct: None,
                doctype: None,
                credential_type: None,
                credential_configuration_id: None,
                status: None,
            },
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&cred).unwrap();
        let deserialized: Credential = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized, cred);
        assert!(json.contains("\"format\":\"dc_sd_jwt\""));
    }
}
