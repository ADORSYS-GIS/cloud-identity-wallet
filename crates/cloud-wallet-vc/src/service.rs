//! Credential service
use chrono::Utc;
use uuid::Uuid;

use crate::{
    credential::Credential,
    repository::{CredentialFilter, CredentialRepository, StoreError},
};

/// Credential storage service.
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

    /// Retrieve a credential by its wallet-internal ID regardless of expiry.
    pub async fn get(&self, id: Uuid) -> Result<Credential, StoreError> {
        self.repo.find_by_id(id).await
    }

    /// Return all stored credentials (including expired ones).
    pub async fn list(&self) -> Result<Vec<Credential>, StoreError> {
        self.repo.find_all().await
    }

    /// Return credentials matching the given filter.
    pub async fn search(&self, filter: CredentialFilter) -> Result<Vec<Credential>, StoreError> {
        let effective_filter = if filter.not_expired_at.is_some() {
            filter
        } else {
            CredentialFilter {
                not_expired_at: Some(Utc::now()),
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
    pub async fn delete(&self, id: Uuid) -> Result<(), StoreError> {
        self.repo.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialFormat, CredentialMetadata};
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct MockRepo {
        creds: Mutex<Vec<Credential>>,
    }

    #[async_trait]
    impl CredentialRepository for MockRepo {
        async fn store(&self, credential: Credential) -> Result<(), StoreError> {
            self.creds.lock().unwrap().push(credential);
            Ok(())
        }
        async fn find_by_id(&self, id: Uuid) -> Result<Credential, StoreError> {
            self.creds
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or(StoreError::NotFound(id))
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
                Err(StoreError::NotFound(credential.id))
            }
        }
        async fn delete(&self, id: Uuid) -> Result<(), StoreError> {
            let mut lock = self.creds.lock().unwrap();
            if let Some(pos) = lock.iter().position(|c| c.id == id) {
                lock.remove(pos);
                Ok(())
            } else {
                Err(StoreError::NotFound(id))
            }
        }
    }

    #[tokio::test]
    async fn test_service_search_expiry_default() {
        let repo = MockRepo {
            creds: Mutex::new(vec![]),
        };
        let service = CredentialService::new(repo);

        let now = Utc::now();
        let id_exp = Uuid::new_v4();
        let cred_expired = Credential {
            id: id_exp,
            format: CredentialFormat::DcSdJwt,
            raw_credential: "raw".to_string(),
            metadata: CredentialMetadata {
                iss: "iss".to_string(),
                iat: now - chrono::Duration::hours(2),
                exp: Some(now - chrono::Duration::hours(1)),
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

        service.store(cred_expired).await.unwrap();

        // Search without filter should exclude expired by default
        let results = service.search(CredentialFilter::default()).await.unwrap();
        assert!(results.is_empty());

        // Search with explicit past timestamp should find it
        let results = service
            .search(CredentialFilter {
                not_expired_at: Some(now - chrono::Duration::hours(10)),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }
}
