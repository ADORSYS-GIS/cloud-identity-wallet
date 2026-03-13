//! High-level credential storage service.

use crate::{
    errors::StoreError,
    models::{Credential, CredentialId},
    repository::{CredentialFilter, CredentialRepository},
};

/// Credential storage service.
///
/// Wraps a [`CredentialRepository`] and adds higher-level conveniences such as
/// automatically filtering out expired credentials in [`Self::search`].
pub struct CredentialService<R: CredentialRepository> {
    repo: R,
}

impl<R: CredentialRepository> CredentialService<R> {
    /// Create a service backed by the given repository.
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    /// Store a new credential.
    pub async fn store(&self, credential: Credential) -> Result<(), StoreError> {
        self.repo.store(credential).await
    }

    /// Retrieve a credential by its wallet-internal ID, regardless of status or expiry.
    pub async fn get(&self, id: &CredentialId) -> Result<Credential, StoreError> {
        self.repo.find_by_id(id).await
    }

    /// Return all stored credentials (including expired and revoked ones).
    pub async fn list(&self) -> Result<Vec<Credential>, StoreError> {
        self.repo.find_all().await
    }

    /// Return credentials matching the given filter.
    ///
    /// If `filter.active_at` is `None`, it is automatically set to the current
    /// UTC timestamp so that expired credentials are excluded by default.
    pub async fn search(&self, filter: CredentialFilter) -> Result<Vec<Credential>, StoreError> {
        let effective_filter = if filter.active_at.is_some() {
            filter
        } else {
            CredentialFilter {
                active_at: Some(time::OffsetDateTime::now_utc()),
                ..filter
            }
        };
        self.repo.find_by_filter(effective_filter).await
    }

    /// Overwrite an existing credential record (e.g. after a refresh flow).
    pub async fn refresh(&self, credential: Credential) -> Result<(), StoreError> {
        self.repo.update(credential).await
    }

    /// Delete a credential by ID.
    pub async fn delete(&self, id: &CredentialId) -> Result<(), StoreError> {
        self.repo.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Binding, Claims, CredentialMetadata, CredentialStatus, CredentialType};
    use serde_json::json;
    use std::sync::Mutex;
    use time::{Duration, OffsetDateTime};

    struct MockRepo {
        creds: Mutex<Vec<Credential>>,
    }

    impl CredentialRepository for MockRepo {
        async fn store(&self, credential: Credential) -> Result<(), StoreError> {
            self.creds.lock().unwrap().push(credential);
            Ok(())
        }

        async fn find_by_id(&self, id: &CredentialId) -> Result<Credential, StoreError> {
            self.creds
                .lock()
                .unwrap()
                .iter()
                .find(|c| &c.id == id)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(id.clone()))
        }

        async fn find_all(&self) -> Result<Vec<Credential>, StoreError> {
            Ok(self.creds.lock().unwrap().clone())
        }

        async fn find_by_filter(
            &self,
            filter: CredentialFilter,
        ) -> Result<Vec<Credential>, StoreError> {
            Ok(self
                .creds
                .lock()
                .unwrap()
                .iter()
                .filter(|c| filter.matches(c))
                .cloned()
                .collect())
        }

        async fn update(&self, credential: Credential) -> Result<(), StoreError> {
            let mut lock = self.creds.lock().unwrap();
            if let Some(pos) = lock.iter().position(|c| c.id == credential.id) {
                lock[pos] = credential;
                Ok(())
            } else {
                Err(StoreError::NotFound(credential.id.clone()))
            }
        }

        async fn delete(&self, id: &CredentialId) -> Result<(), StoreError> {
            let mut lock = self.creds.lock().unwrap();
            if let Some(pos) = lock.iter().position(|c| &c.id == id) {
                lock.remove(pos);
                Ok(())
            } else {
                Err(StoreError::NotFound(id.clone()))
            }
        }
    }

    fn make_cred(expired: bool) -> Credential {
        let now = OffsetDateTime::now_utc();
        let expires_at = if expired {
            Some(now - Duration::hours(1))
        } else {
            Some(now + Duration::days(365))
        };
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("identity_credential"),
            Claims::new(json!({ "given_name": "Alice" })),
            now - Duration::hours(2),
            expires_at,
            None, // status_reference
            Binding,
            CredentialMetadata {},
        )
        .expect("valid credential")
    }

    #[tokio::test]
    async fn search_excludes_expired_by_default() {
        let service = CredentialService::new(MockRepo {
            creds: Mutex::new(vec![]),
        });

        let expired = make_cred(true);
        service.store(expired).await.unwrap();

        // No active_at in filter → defaults to now → expired credential is excluded
        let results = service.search(CredentialFilter::default()).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn search_includes_non_expired() {
        let service = CredentialService::new(MockRepo {
            creds: Mutex::new(vec![]),
        });

        let active = make_cred(false);
        service.store(active).await.unwrap();

        let results = service.search(CredentialFilter::default()).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn get_returns_credential_regardless_of_expiry() {
        let service = CredentialService::new(MockRepo {
            creds: Mutex::new(vec![]),
        });

        let expired = make_cred(true);
        let id = expired.id.clone();
        service.store(expired).await.unwrap();

        // get() bypasses expiry filtering
        assert!(service.get(&id).await.is_ok());
    }

    #[tokio::test]
    async fn delete_removes_credential() {
        let service = CredentialService::new(MockRepo {
            creds: Mutex::new(vec![]),
        });

        let cred = make_cred(false);
        let id = cred.id.clone();
        service.store(cred).await.unwrap();
        service.delete(&id).await.unwrap();

        let result = service.get(&id).await;
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn refresh_updates_credential() {
        let service = CredentialService::new(MockRepo {
            creds: Mutex::new(vec![]),
        });

        let cred = make_cred(false);
        let id = cred.id.clone();
        service.store(cred).await.unwrap();

        let mut updated = service.get(&id).await.unwrap();
        updated.status = CredentialStatus::Revoked;
        service.refresh(updated).await.unwrap();

        let fetched = service.get(&id).await.unwrap();
        assert_eq!(fetched.status, CredentialStatus::Revoked);
    }
}
