//! Transparent encryption adapter for any [`CredentialRepository<StoredCredential>`].
//!
//! [`EncryptingRepository`] implements `CredentialRepository<Credential>` — the
//! standard high-level interface — by delegating to an inner backend that
//! implements `CredentialRepository<StoredCredential>`.
//!
//! There is no duplicate trait: both layers use the **same** generic
//! [`CredentialRepository<T>`] port, just with different type parameters.
//!
//! # Example
//!
//! ```rust,ignore
//! let kek = Kek::from_bytes(load_32_bytes_from_kms())?;
//! let backend = PostgresCredentialRepository::from_config(&cfg).await?;
//! let repo = EncryptingRepository::new(backend, kek);
//! // repo implements CredentialRepository<Credential> transparently
//! let svc = CredentialService::new(repo);
//! ```

use crate::{
    encryption::{Kek, StoredCredential, decrypt_credential, encrypt_credential},
    errors::StoreError,
    models::{Credential, CredentialId},
    repository::{CredentialFilter, CredentialRepository},
};

/// Transparent encryption adapter.
///
/// Wraps any `R: CredentialRepository<StoredCredential>` (the encrypted
/// storage backend) and implements `CredentialRepository<Credential>` (the
/// plain wallet-facing interface). Encryption happens on every write;
/// decryption happens on every read. No credentials leave the adapter
/// unencrypted.
pub struct EncryptingRepository<R: CredentialRepository<StoredCredential>> {
    inner: R,
    kek: Kek,
}

impl<R: CredentialRepository<StoredCredential>> EncryptingRepository<R> {
    /// Wrap `inner` with the given `kek`.
    pub fn new(inner: R, kek: Kek) -> Self {
        Self { inner, kek }
    }
}

impl<R: CredentialRepository<StoredCredential>> CredentialRepository<Credential>
    for EncryptingRepository<R>
{
    async fn store(&self, credential: Credential) -> Result<(), StoreError> {
        let stored = encrypt_credential(&self.kek, &credential)?;
        self.inner.store(stored).await
    }

    async fn find_by_id(&self, id: &CredentialId) -> Result<Credential, StoreError> {
        let stored = self.inner.find_by_id(id).await?;
        decrypt_credential(&self.kek, &stored)
    }

    async fn find_all(&self) -> Result<Vec<Credential>, StoreError> {
        let all = self.inner.find_all().await?;
        let tasks = all.into_iter().map(|s| {
            let kek = self.kek.clone();
            async move { decrypt_credential(&kek, &s) }
        });
        futures::future::try_join_all(tasks).await
    }

    async fn find_by_filter(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<Credential>, StoreError> {
        // Filtering is pushed down to the inner repo (SQL for Postgres;
        // plaintext-field matching for in-memory). Decryption happens after.
        let matched = self.inner.find_by_filter(filter).await?;
        let tasks = matched.into_iter().map(|s| {
            let kek = self.kek.clone();
            async move { decrypt_credential(&kek, &s) }
        });
        futures::future::try_join_all(tasks).await
    }

    async fn update(&self, credential: Credential) -> Result<(), StoreError> {
        let stored = encrypt_credential(&self.kek, &credential)?;
        self.inner.update(stored).await
    }

    async fn delete(&self, id: &CredentialId) -> Result<(), StoreError> {
        self.inner.delete(id).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::StoredCredential;
    use crate::models::{Binding, Claims, CredentialMetadata, CredentialType};
    use serde_json::json;
    use std::sync::Mutex;
    use time::{Duration, OffsetDateTime};

    /// In-memory backend implementing `CredentialRepository<StoredCredential>`.
    ///
    /// This is the pattern any concrete storage backend (Postgres, SQLite…)
    /// would follow — implement the generic `CredentialRepository<StoredCredential>`,
    /// then compose with `EncryptingRepository` to get the plaintext interface.
    struct InMemBackend {
        records: Mutex<Vec<StoredCredential>>,
    }

    impl InMemBackend {
        fn new() -> Self {
            Self {
                records: Mutex::new(vec![]),
            }
        }
    }

    impl CredentialRepository<StoredCredential> for InMemBackend {
        async fn store(&self, item: StoredCredential) -> Result<(), StoreError> {
            let mut lock = self.records.lock().unwrap();
            if lock.iter().any(|r| r.id == item.id) {
                return Err(StoreError::DuplicateId(item.id));
            }
            lock.push(item);
            Ok(())
        }

        async fn find_by_id(&self, id: &CredentialId) -> Result<StoredCredential, StoreError> {
            self.records
                .lock()
                .unwrap()
                .iter()
                .find(|r| &r.id == id)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(id.clone()))
        }

        async fn find_all(&self) -> Result<Vec<StoredCredential>, StoreError> {
            Ok(self.records.lock().unwrap().clone())
        }

        async fn find_by_filter(
            &self,
            filter: CredentialFilter,
        ) -> Result<Vec<StoredCredential>, StoreError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.matches_filter(&filter))
                .cloned()
                .collect())
        }

        async fn update(&self, item: StoredCredential) -> Result<(), StoreError> {
            let mut lock = self.records.lock().unwrap();
            match lock.iter().position(|r| r.id == item.id) {
                Some(pos) => {
                    lock[pos] = item;
                    Ok(())
                }
                None => Err(StoreError::NotFound(item.id)),
            }
        }

        async fn delete(&self, id: &CredentialId) -> Result<(), StoreError> {
            let mut lock = self.records.lock().unwrap();
            if let Some(pos) = lock.iter().position(|r| &r.id == id) {
                lock.remove(pos);
                Ok(())
            } else {
                Err(StoreError::NotFound(id.clone()))
            }
        }
    }

    fn make_credential() -> Credential {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("https://credentials.example.com/id"),
            Claims::new(json!({ "given_name": "Alice" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            CredentialMetadata {},
        )
        .expect("valid credential")
    }

    #[tokio::test]
    async fn store_and_retrieve_is_transparent() {
        let kek = Kek::generate().unwrap();
        let repo = EncryptingRepository::new(InMemBackend::new(), kek);

        let cred = make_credential();
        let id = cred.id.clone();
        repo.store(cred.clone()).await.unwrap();

        let retrieved = repo.find_by_id(&id).await.unwrap();
        assert_eq!(retrieved.id, cred.id);
        assert_eq!(retrieved.issuer, cred.issuer);
        assert_eq!(retrieved.claims["given_name"], "Alice");
    }

    #[tokio::test]
    async fn update_re_encrypts_credential() {
        let kek = Kek::generate().unwrap();
        let repo = EncryptingRepository::new(InMemBackend::new(), kek);

        let cred = make_credential();
        let id = cred.id.clone();
        repo.store(cred).await.unwrap();

        let mut updated = repo.find_by_id(&id).await.unwrap();
        updated.issuer = "https://new-issuer.example.com".into();
        repo.update(updated).await.unwrap();

        assert_eq!(
            repo.find_by_id(&id).await.unwrap().issuer,
            "https://new-issuer.example.com"
        );
    }

    #[tokio::test]
    async fn delete_removes_credential() {
        let kek = Kek::generate().unwrap();
        let repo = EncryptingRepository::new(InMemBackend::new(), kek);
        let cred = make_credential();
        let id = cred.id.clone();
        repo.store(cred).await.unwrap();
        repo.delete(&id).await.unwrap();
        assert!(matches!(
            repo.find_by_id(&id).await,
            Err(StoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn filter_by_issuer_works_on_plaintext_metadata() {
        let kek = Kek::generate().unwrap();
        let repo = EncryptingRepository::new(InMemBackend::new(), kek);
        repo.store(make_credential()).await.unwrap();

        let hits = repo
            .find_by_filter(CredentialFilter {
                issuer: Some("https://issuer.example.com".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);

        let misses = repo
            .find_by_filter(CredentialFilter {
                issuer: Some("https://other.example.com".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(misses.is_empty());
    }

    #[tokio::test]
    async fn find_all_decrypts_all_records() {
        let kek = Kek::generate().unwrap();
        let repo = EncryptingRepository::new(InMemBackend::new(), kek);
        repo.store(make_credential()).await.unwrap();
        repo.store(make_credential()).await.unwrap();
        let all = repo.find_all().await.unwrap();
        assert_eq!(all.len(), 2);
        for c in &all {
            assert_eq!(c.claims["given_name"], "Alice");
        }
    }
}
