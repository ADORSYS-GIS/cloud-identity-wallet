use std::sync::Arc;

use async_trait::async_trait;
use cloud_wallet_kms::provider::Provider as KmsProvider;
use dashmap::DashMap;
use uuid::Uuid;

use crate::credential::Credential;
use crate::storage::cipher::{self, Cipher};
use crate::storage::{CredentialFilter, CredentialRepository, Error, Result};

#[derive(Clone)]
struct StoredCredential {
    credential: Credential,
    raw_credential: Vec<u8>,
    payload_encrypted: bool,
}

/// A volatile, in-memory credential storage backend.
///
/// Useful for tests or local development where data persistence across restarts
/// is not required.
#[derive(Clone)]
pub struct InMemoryRepository {
    credentials: Arc<DashMap<(Uuid, Uuid), StoredCredential>>,
    cipher: Option<Arc<dyn Cipher>>,
}

impl std::fmt::Debug for InMemoryRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryRepository")
            .field("credentials_len", &self.credentials.len())
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl Default for InMemoryRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRepository {
    /// Creates a new, empty in-memory repository.
    pub fn new() -> Self {
        Self {
            credentials: Arc::default(),
            cipher: None,
        }
    }

    /// Configures the repository with a KMS provider for encrypting credential payloads.
    ///
    /// By default, the `InMemoryRepository` does not encrypt data. Calling this method
    /// enables payload encryption and decryption using the provided KMS provider.
    pub fn with_cipher<K: KmsProvider + Send + Sync + 'static>(provider: K) -> Self {
        Self {
            credentials: Arc::default(),
            cipher: Some(cipher::from_provider(provider)),
        }
    }

    /// Encrypts the raw credential payload if a cipher is configured.
    async fn maybe_encrypt(&self, id: &Uuid, raw_credential: &mut Vec<u8>) -> Result<bool> {
        if let Some(cipher) = &self.cipher {
            cipher
                .encrypt(id.as_bytes(), raw_credential)
                .await
                .map_err(|e| Error::Encryption(e.to_string()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Decrypts the raw credential payload if it was previously encrypted.
    async fn maybe_decrypt(&self, entry: &StoredCredential) -> Result<Credential> {
        let mut credential = entry.credential.clone();
        let mut raw_credential = entry.raw_credential.clone();

        if entry.payload_encrypted {
            let Some(cipher) = &self.cipher else {
                return Err(Error::Other(
                    "credential payload is encrypted but no cipher is configured".into(),
                ));
            };

            let dst = raw_credential.as_ptr() as usize;
            let plaintext = cipher
                .decrypt(credential.id.as_bytes(), raw_credential.as_mut_slice())
                .await
                .map_err(|e| Error::Encryption(e.to_string()))?;
            let src = plaintext.as_ptr() as usize;
            let plaintext_len = plaintext.len();
            let offset = src.checked_sub(dst).ok_or_else(|| {
                Error::InvalidData("decrypted plaintext is not backed by source buffer".into())
            })?;
            compact_plaintext_in_place(&mut raw_credential, offset, plaintext_len)?;
        }
        credential.raw_credential = raw_credential_from_bytes(raw_credential)?;
        Ok(credential)
    }
}

/// Helper function to compact the plaintext in place after decryption.
fn compact_plaintext_in_place(
    buffer: &mut Vec<u8>,
    plaintext_offset: usize,
    plaintext_len: usize,
) -> Result<()> {
    let end = plaintext_offset + plaintext_len;
    if end > buffer.len() {
        return Err(Error::InvalidData(
            "decrypted plaintext is outside source buffer".to_string(),
        ));
    }

    if plaintext_offset > 0 {
        buffer.copy_within(plaintext_offset..end, 0);
    }
    buffer.truncate(plaintext_len);
    Ok(())
}

fn raw_credential_from_bytes(value: Vec<u8>) -> Result<String> {
    String::from_utf8(value).map_err(|e| Error::InvalidData(format!("invalid raw credential: {e}")))
}

#[async_trait]
impl CredentialRepository for InMemoryRepository {
    async fn upsert(&self, mut credential: Credential) -> Result<Uuid> {
        let credential_id = credential.id;
        let mut raw_credential = std::mem::take(&mut credential.raw_credential).into_bytes();
        let payload_encrypted = self
            .maybe_encrypt(&credential.id, &mut raw_credential)
            .await?;
        let key = (credential.tenant_id, credential.id);
        self.credentials.insert(
            key,
            StoredCredential {
                credential,
                raw_credential,
                payload_encrypted,
            },
        );
        Ok(credential_id)
    }

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let entry = self
            .credentials
            .get(&(tenant_id, id))
            .ok_or(Error::NotFound { id, tenant_id })?;
        self.maybe_decrypt(entry.value()).await
    }

    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>> {
        let mut out = Vec::with_capacity(self.credentials.len());

        for entry in self.credentials.iter() {
            let stored = entry.value();

            if filter.matches(&stored.credential) {
                out.push(self.maybe_decrypt(stored).await?);
            }
        }

        out.sort_by(|a, b| b.issued_at.cmp(&a.issued_at));
        Ok(out)
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<()> {
        self.credentials
            .remove(&(tenant_id, id))
            .ok_or(Error::NotFound { id, tenant_id })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use time::UtcDateTime;
    use url::Url;
    use uuid::Uuid;

    use crate::credential::{Credential, CredentialFormat, CredentialStatus};
    use crate::storage::memory::InMemoryRepository;
    use crate::storage::{CredentialFilter, CredentialRepository};
    use cloud_wallet_kms::provider::Provider as KmsProvider;

    #[derive(Debug, Clone, Copy)]
    struct PrefixCipher;

    const PREFIX: &[u8] = b"encrypted:";

    #[async_trait]
    impl KmsProvider for PrefixCipher {
        async fn encrypt<T>(
            &self,
            _key_id: &[u8],
            plaintext: &mut T,
        ) -> cloud_wallet_kms::Result<()>
        where
            T: AsMut<[u8]> + for<'a> Extend<&'a u8> + Send,
        {
            plaintext.extend(PREFIX.iter());
            let payload = plaintext.as_mut();
            let plaintext_len = payload.len() - PREFIX.len();
            payload.copy_within(0..plaintext_len, PREFIX.len());
            payload[..PREFIX.len()].copy_from_slice(PREFIX);
            Ok(())
        }

        async fn decrypt<'a>(
            &self,
            _key_id: &[u8],
            ciphertext: &'a mut [u8],
        ) -> cloud_wallet_kms::Result<&'a [u8]> {
            if ciphertext.starts_with(PREFIX) {
                Ok(&ciphertext[PREFIX.len()..])
            } else {
                Err(cloud_wallet_kms::Error::Other("invalid prefix".to_string()))
            }
        }
    }

    fn sample_credential(tenant_id: Uuid) -> Credential {
        Credential {
            id: Uuid::new_v4(),
            tenant_id,
            issuer: "https://issuer.example".to_string(),
            subject: Some("did:example:alice".to_string()),
            credential_types: vec![
                "VerifiableCredential".to_string(),
                "EmployeeBadge".to_string(),
            ],
            format: CredentialFormat::JwtVcJson,
            external_id: Some("ext-123".to_string()),
            status: CredentialStatus::Active,
            issued_at: UtcDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            valid_until: Some(UtcDateTime::from_unix_timestamp(2_000_000_000).unwrap()),
            is_revoked: false,
            status_location: Some(Url::parse("https://status.example/1").unwrap()),
            status_index: Some(7),
            raw_credential: "{\"vc\":\"payload\"}".to_string(),
        }
    }

    #[tokio::test]
    async fn in_memory_crud_roundtrip() {
        let repo = InMemoryRepository::with_cipher(PrefixCipher);
        let tenant_id = Uuid::new_v4();
        let credential = sample_credential(tenant_id);

        repo.upsert(credential.clone()).await.unwrap();

        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();
        assert_eq!(found.id, credential.id);
        assert_eq!(found.raw_credential, credential.raw_credential);

        let listed = repo
            .list(CredentialFilter {
                tenant_id: Some(tenant_id),
                format: Some(CredentialFormat::JwtVcJson),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        repo.delete(credential.id, tenant_id).await.unwrap();
        assert!(repo.find_by_id(credential.id, tenant_id).await.is_err());
    }

    #[tokio::test]
    async fn in_memory_with_cipher_decrypts_on_read() {
        let repo = InMemoryRepository::with_cipher(PrefixCipher);
        let tenant_id = Uuid::new_v4();
        let credential = sample_credential(tenant_id);

        repo.upsert(credential.clone()).await.unwrap();
        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();

        assert_eq!(found.raw_credential, credential.raw_credential);
    }
}
