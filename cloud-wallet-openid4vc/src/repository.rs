//! Repository port: the async trait that all credential storage backends must implement.

use crate::errors::StoreError;
use crate::models::{Credential, CredentialId, CredentialStatus, CredentialType};

/// Filter parameters for querying credentials.
#[derive(Debug, Default, Clone)]
pub struct CredentialFilter {
    /// Only return credentials issued by this issuer.
    pub issuer: Option<String>,

    /// Only return credentials for this subject.
    pub subject: Option<String>,

    /// Only return credentials with this lifecycle status.
    pub status: Option<CredentialStatus>,

    /// Only return credentials with this credential type.
    pub credential_type: Option<CredentialType>,

    /// When set, exclude credentials whose `expires_at` is `Some` and in the past
    /// relative to this timestamp. Credentials with no expiry are always included.
    pub active_at: Option<time::OffsetDateTime>,
}

impl CredentialFilter {
    /// Returns `true` if `credential` matches all conditions in this filter.
    pub fn matches(&self, credential: &Credential) -> bool {
        if let Some(ref issuer) = self.issuer
            && &credential.issuer != issuer
        {
            return false;
        }
        if let Some(ref subject) = self.subject
            && &credential.subject != subject
        {
            return false;
        }
        if let Some(ref status) = self.status
            && &credential.status != status
        {
            return false;
        }
        if let Some(ref cred_type) = self.credential_type
            && &credential.credential_type != cred_type
        {
            return false;
        }
        if let Some(active_at) = self.active_at
            && let Some(expires) = credential.expires_at
            && expires <= active_at
        {
            return false;
        }
        true
    }
}

/// Async CRUD port for credential persistence.
///
/// The type parameter `T` is the stored item type. It defaults to [`Credential`],
/// which is what all high-level callers (e.g. [`CredentialService`]) use.
/// The `encryption` feature introduces a second impl where `T = StoredCredential`
/// so the same trait serves both the plain and the encrypted storage layers.
///
/// [`CredentialService`]: crate::CredentialService
#[allow(async_fn_in_trait)]
pub trait CredentialRepository<T = Credential>: Send + Sync {
    /// Persist a new item. Returns [`StoreError::DuplicateId`] if the ID already exists.
    async fn store(&self, item: T) -> Result<(), StoreError>;

    /// Retrieve an item by its wallet-internal ID.
    async fn find_by_id(&self, id: &CredentialId) -> Result<T, StoreError>;

    /// Return all stored items (unordered).
    async fn find_all(&self) -> Result<Vec<T>, StoreError>;

    /// Return all items matching the given filter.
    async fn find_by_filter(&self, filter: CredentialFilter) -> Result<Vec<T>, StoreError>;

    /// Overwrite an existing record.
    async fn update(&self, item: T) -> Result<(), StoreError>;

    /// Remove an item by ID.
    async fn delete(&self, id: &CredentialId) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Binding, Claims, CredentialMetadata, CredentialType};
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    fn make_credential(
        issuer: &str,
        subject: &str,
        status: CredentialStatus,
        expires_at: Option<OffsetDateTime>,
    ) -> Credential {
        // issued_at must be strictly before expires_at; use 2h ago so a past expiry can still be valid
        let issued_at = match expires_at {
            Some(exp) => exp - Duration::hours(1),
            None => OffsetDateTime::now_utc(),
        };
        Credential::new(
            issuer,
            subject,
            CredentialType::new("https://credentials.example.com/id"),
            Claims::new(json!({ "given_name": "Alice" })),
            issued_at,
            expires_at,
            None,
            Binding,
            CredentialMetadata {},
        )
        .map(|mut c| {
            c.status = status;
            c
        })
        .expect("valid test credential")
    }

    #[test]
    fn filter_matches_by_issuer() {
        let cred = make_credential(
            "https://issuer.example.com",
            "user-1",
            CredentialStatus::Active,
            None,
        );

        let matching = CredentialFilter {
            issuer: Some("https://issuer.example.com".to_owned()),
            ..Default::default()
        };
        assert!(matching.matches(&cred));

        let non_matching = CredentialFilter {
            issuer: Some("https://other.example.com".to_owned()),
            ..Default::default()
        };
        assert!(!non_matching.matches(&cred));
    }

    #[test]
    fn filter_matches_by_status() {
        let cred = make_credential(
            "https://issuer.example.com",
            "user-1",
            CredentialStatus::Revoked,
            None,
        );

        let matching = CredentialFilter {
            status: Some(CredentialStatus::Revoked),
            ..Default::default()
        };
        assert!(matching.matches(&cred));

        let non_matching = CredentialFilter {
            status: Some(CredentialStatus::Active),
            ..Default::default()
        };
        assert!(!non_matching.matches(&cred));
    }

    #[test]
    fn filter_excludes_expired_when_active_at_set() {
        let past = OffsetDateTime::now_utc() - Duration::hours(1);
        let cred = make_credential(
            "https://issuer.example.com",
            "user-1",
            CredentialStatus::Active,
            Some(past),
        );

        // active_at = now → credential already expired
        let filter = CredentialFilter {
            active_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };
        assert!(!filter.matches(&cred));
    }

    #[test]
    fn filter_includes_non_expired_when_active_at_set() {
        let future = OffsetDateTime::now_utc() + Duration::hours(1);
        let cred = make_credential(
            "https://issuer.example.com",
            "user-1",
            CredentialStatus::Active,
            Some(future),
        );

        let filter = CredentialFilter {
            active_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };
        assert!(filter.matches(&cred));
    }

    #[test]
    fn filter_includes_no_expiry_credentials_when_active_at_set() {
        let cred = make_credential(
            "https://issuer.example.com",
            "user-1",
            CredentialStatus::Active,
            None,
        );

        let filter = CredentialFilter {
            active_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };
        // No expiry → always included
        assert!(filter.matches(&cred));
    }
}
