use std::sync::Arc;

use cloud_wallet_crypto as crypto;
use cloud_wallet_crypto::aead::{Algorithm, Key, NONCE_LENGTH, TAG_LENGTH};
use cloud_wallet_crypto::secret::Secret;
use color_eyre::eyre::eyre;
use tokio::sync::OnceCell;

use crate::key::{
    dek::{DataEncryptionKey, Id as DekId},
    master::{Id as MasterId, Metadata},
};
use crate::nonce::NonceGenerator;
use crate::provider::Provider;
use crate::storage::{InMemoryBackend, Storage};
use crate::{AeadAlgorithm, Error, Result};

const HOSTNAME: &str = "localhost";

#[derive(Clone, Debug)]
struct MasterKey {
    metadata: Metadata,
    material: Secret,
}

/// A KMS [`Provider`] that uses a locally managed, in-memory master key.
///
/// This provider is designed for local development and testing.
#[derive(Debug)]
pub struct LocalProvider<S = InMemoryBackend> {
    master_key: Arc<OnceCell<MasterKey>>,
    master_id: MasterId,
    dek_id: DekId,
    storage: S,
    nonce_gen: NonceGenerator,
}

impl LocalProvider {
    /// Creates a new `LocalProvider` with an in-memory storage backend.
    pub fn new() -> Self {
        Self::with_storage(InMemoryBackend::new())
    }
}

impl<S: Storage> LocalProvider<S> {
    /// Creates a new `LocalProvider` with the specified storage backend.
    pub fn with_storage(storage: S) -> Self {
        // Generate deterministic IDs
        let master_id = MasterId::new(HOSTNAME);
        let dek_id = DekId::new(HOSTNAME);

        let mut prefix = [0u8; 4];
        rand::fill(&mut prefix);
        let nonce_gen = NonceGenerator::new().with_prefix(prefix);

        Self {
            master_key: Arc::new(OnceCell::new()),
            master_id,
            dek_id,
            storage,
            nonce_gen,
        }
    }

    /// Ensures the master key is initialized.
    async fn get_or_try_init_master_key(&self) -> Result<MasterKey> {
        let master_id = self.master_id.clone();
        self.master_key
            .get_or_try_init(|| async {
                // Generate 256-bit master key
                let mut key_material = zeroize::Zeroizing::new([0u8; 32]);
                crypto::rand::fill_bytes(&mut key_material[..])?;

                let master_key = MasterKey {
                    metadata: Metadata::new(master_id, AeadAlgorithm::from(Algorithm::AesGcm256)),
                    material: Secret::from(key_material.as_slice()),
                };
                Ok(master_key)
            })
            .await
            .cloned()
    }

    /// Ensures the DEK exists in storage or creates it.
    async fn get_or_try_init_dek(&self) -> Result<DataEncryptionKey> {
        // Check storage first
        if let Some(dek) = self.storage.get_dek(&self.dek_id).await? {
            return Ok(dek);
        }

        let master_key = self.get_or_try_init_master_key().await?;

        // Generate 256-bit DEK
        let alg = Algorithm::AesGcm256;
        let mut material = zeroize::Zeroizing::new([0u8; 32]);
        crypto::rand::fill_bytes(&mut material[..])?;

        // Encrypt DEK with master key
        let nonce = self.nonce_gen.next()?;
        let mut ciphertext = material.as_ref().to_vec();
        let key = Key::new(
            master_key.metadata.algorithm.into(),
            master_key.material.expose(),
        )?;
        key.encrypt_append_tag(&nonce, [], &mut ciphertext)?;
        ciphertext.extend(nonce);

        let dek = DataEncryptionKey::new(
            self.dek_id.clone(),
            self.master_id.clone(),
            None,
            ciphertext,
            AeadAlgorithm::from(alg),
        );

        self.storage.upsert_dek(&dek).await?;
        Ok(dek)
    }

    /// Gets the plaintext DEK
    async fn get_plaintext_dek(&self) -> Result<Secret> {
        // Get encrypted DEK from storage
        let dek = self.get_or_try_init_dek().await?;
        let master_key = self.get_or_try_init_master_key().await?;

        // Extract all necessary data before any crypto operations
        let algorithm = master_key.metadata.algorithm.into();
        let none_start = dek.encrypted_key.len() - NONCE_LENGTH;
        let nonce: [u8; NONCE_LENGTH] = dek.encrypted_key[none_start..].try_into().unwrap();
        let encrypted_key = dek.encrypted_key[..none_start].to_vec();

        // Decrypt DEK
        let key = Key::new(algorithm, master_key.material.expose())?;
        let mut cipher_inout = zeroize::Zeroizing::new(encrypted_key);
        let plaintext_dek = key.decrypt(&nonce, [], &mut cipher_inout)?;
        Ok(Secret::from(&*plaintext_dek))
    }
}

#[async_trait::async_trait]
impl<S: Storage> Provider for LocalProvider<S> {
    async fn encrypt<T>(&self, aad: &[u8], plain_inout: &mut T) -> crate::Result<()>
    where
        T: AsMut<[u8]> + for<'a> Extend<&'a u8> + Send,
    {
        // Get DEK
        let dek = self.get_plaintext_dek().await?;

        // Encrypt data with DEK
        let key = Key::new(Algorithm::AesGcm256, dek.expose())?;
        let nonce = self.nonce_gen.next()?;
        key.encrypt_append_tag(&nonce, aad, plain_inout)?;
        // Append nonce to the end of the buffer
        plain_inout.extend(nonce.iter());
        Ok(())
    }

    async fn decrypt<'a>(&self, aad: &[u8], cipher_inout: &'a mut [u8]) -> Result<&'a [u8]> {
        // Validate input format: ciphertext || tag || nonce
        if cipher_inout.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(Error::Crypto(eyre!("Invalid ciphertext blob")));
        }

        let nonce_start = cipher_inout.len() - NONCE_LENGTH;
        // Safety: We know the length is correct from the calculation above
        let nonce: [u8; NONCE_LENGTH] = cipher_inout[nonce_start..].try_into().unwrap();

        // Get DEK
        let dek = self.get_plaintext_dek().await?;

        // Decrypt data with DEK
        let key = Key::new(Algorithm::AesGcm256, dek.expose())?;
        let encrypted_slice = &mut cipher_inout[..nonce_start];
        let plaintext_dek = key.decrypt(&nonce, aad, encrypted_slice)?;
        Ok(plaintext_dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let provider = LocalProvider::new();

        let mut plaintext = b"Hello, world!".to_vec();
        let aad = b"additional authenticated data";

        // Encrypt
        provider.encrypt(aad, &mut plaintext).await.unwrap();

        // Decrypt
        let mut decrypted = plaintext.clone();
        let result = provider.decrypt(aad, &mut decrypted).await.unwrap();

        assert_eq!(b"Hello, world!", result);
    }

    #[tokio::test]
    async fn test_basic_operations() {
        let provider = LocalProvider::new();

        // Test encryption
        let mut data1 = b"First message".to_vec();
        let aad1 = b"additional authenticated data 1";
        provider.encrypt(aad1, &mut data1).await.unwrap();

        let mut data2 = b"Second message".to_vec();
        let aad2 = b"additional authenticated data 2";
        provider.encrypt(aad2, &mut data2).await.unwrap();

        // Test decryption
        let mut decrypted1 = data1.clone();
        let result1 = provider.decrypt(aad1, &mut decrypted1).await.unwrap();
        assert_eq!(b"First message", result1);

        let mut decrypted2 = data2.clone();
        let result2 = provider.decrypt(aad2, &mut decrypted2).await.unwrap();
        assert_eq!(b"Second message", result2);
    }

    #[tokio::test]
    async fn test_decryption_failure_corrupted_data() {
        let provider = LocalProvider::new();

        // Encrypt
        let mut data = b"Message".to_vec();
        provider.encrypt(&[], &mut data).await.unwrap();

        // Decrypting corrupted data should fail
        let mut decrypted = data.clone();
        decrypted[0] ^= 1;
        let result = provider.decrypt(&[], &mut decrypted).await;
        assert!(result.is_err());
        if let crate::Error::Crypto(e) = result.unwrap_err() {
            let err = e.downcast::<crypto::Error>().unwrap();
            assert_eq!(err.kind(), crypto::error::ErrorKind::Decryption);
        } else {
            panic!("Expected Crypto error");
        }
    }
}
