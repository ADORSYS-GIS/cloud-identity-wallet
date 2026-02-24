//! Repository port: the async trait that all credential storage backends must implement.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::credential::{Credential, CredentialFormat};

/// Errors that can occur during credential repository operations.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("credential not found: {0}")]
    NotFound(Uuid),
    #[error("credential already exists: {0}")]
    DuplicateId(Uuid),
    #[error("storage error: {0}")]
    Storage(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Filter parameters for querying credentials.
#[derive(Debug, Default, Clone)]
pub struct CredentialFilter {
    pub format: Option<CredentialFormat>,
    pub iss: Option<String>,
    pub vct: Option<String>,
    pub doctype: Option<String>,
    pub sub: Option<String>,
    pub not_expired_at: Option<DateTime<Utc>>,
}

impl CredentialFilter {
    /// Returns `true` if `credential` matches all conditions in this filter.
    pub fn matches(&self, credential: &Credential) -> bool {
        if let Some(ref fmt) = self.format
            && &credential.format != fmt
        {
            return false;
        }
        if let Some(ref iss) = self.iss
            && &credential.metadata.iss != iss
        {
            return false;
        }
        if let Some(ref vct) = self.vct
            && credential.metadata.vct.as_deref() != Some(vct.as_str())
        {
            return false;
        }
        if let Some(ref doctype) = self.doctype
            && credential.metadata.doctype.as_deref() != Some(doctype.as_str())
        {
            return false;
        }
        if let Some(ref sub) = self.sub
            && credential.metadata.sub.as_deref() != Some(sub.as_str())
        {
            return false;
        }
        if let Some(not_expired) = self.not_expired_at
            && credential.is_expired_at(not_expired)
        {
            return false;
        }
        true
    }
}

/// Async CRUD port for credential persistence.
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    /// Persist a new credential.
    async fn store(&self, credential: Credential) -> Result<(), StoreError>;

    /// Retrieve a credential by its wallet-internal ID.
    async fn find_by_id(&self, id: Uuid) -> Result<Credential, StoreError>;

    /// Return all stored credentials (unordered).
    async fn find_all(&self) -> Result<Vec<Credential>, StoreError>;

    /// Return all credentials matching the given filter.
    async fn find_by_filter(&self, filter: CredentialFilter)
    -> Result<Vec<Credential>, StoreError>;

    /// Overwrite an existing credential record.
    async fn update(&self, credential: Credential) -> Result<(), StoreError>;

    /// Remove a credential by ID.
    async fn delete(&self, id: Uuid) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialFormat, CredentialMetadata};
    use chrono::Utc;

    #[test]
    fn test_credential_filter_matches() {
        let now = Utc::now();
        let cred = Credential {
            id: Uuid::new_v4(),
            format: CredentialFormat::DcSdJwt,
            raw_credential: "raw".to_string(),
            metadata: CredentialMetadata {
                iss: "https://issuer.com".to_string(),
                iat: now,
                exp: Some(now + chrono::Duration::hours(1)),
                sub: Some("user1".to_string()),
                vct: Some("Identity".to_string()),
                doctype: None,
                credential_type: None,
                credential_configuration_id: None,
                status: None,
            },
            created_at: now,
            updated_at: now,
        };

        // Matching filter
        let filter = CredentialFilter {
            iss: Some("https://issuer.com".to_string()),
            vct: Some("Identity".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&cred));

        // Mismatching filter (issuer)
        let filter = CredentialFilter {
            iss: Some("https://other.com".to_string()),
            ..Default::default()
        };
        assert!(!filter.matches(&cred));

        // Mismatching filter (format)
        let filter = CredentialFilter {
            format: Some(CredentialFormat::MsoMdoc),
            ..Default::default()
        };
        assert!(!filter.matches(&cred));

        // Expiry filter
        let filter = CredentialFilter {
            not_expired_at: Some(now),
            ..Default::default()
        };
        assert!(filter.matches(&cred));

        let filter = CredentialFilter {
            not_expired_at: Some(now + chrono::Duration::hours(2)),
            ..Default::default()
        };
        assert!(!filter.matches(&cred));
    }
}
