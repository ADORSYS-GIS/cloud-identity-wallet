use cloud_wallet_crypto::secret::Secret;
use time::UtcDateTime;

use crate::{AeadAlgorithm, key::master::Id as MasterKeyId};

/// Represents a Data Encryption Key (DEK).
///
/// DEKs are used for encrypting and decrypting data. They are themselves encrypted with a Master Key
/// to ensure their security. This struct holds both the encrypted and, optionally, the plaintext
/// version of the key, along with metadata.
#[derive(Debug, Clone)]
pub struct DataEncryptionKey {
    /// The unique identifier of the DEK.
    pub id: Id,

    /// The identifier of the Master Key used to encrypt this DEK.
    pub master_key_id: MasterKeyId,

    /// The encrypted DEK material.
    ///
    /// This is the ciphertext of the DEK, which can be safely stored.
    pub encrypted_key: Box<[u8]>,

    /// The plaintext DEK material.
    ///
    /// This is the actual key used for encryption/decryption.
    /// It is wrapped in a `Secret` to prevent accidental exposure.
    /// This field is `None` when the DEK is sealed (i.e., not in use).
    pub plaintext_key: Option<Secret>,

    /// The AEAD algorithm used for encryption with this DEK.
    pub algorithm: AeadAlgorithm,

    /// The timestamp of when the DEK was created.
    pub created_at: UtcDateTime,

    /// The timestamp of the last time the DEK was accessed.
    pub last_accessed: Option<UtcDateTime>,
}

impl DataEncryptionKey {
    /// Creates a new `DataEncryptionKey`.
    ///
    /// This constructor initializes a DEK with its essential properties.
    /// The `plaintext_key` is optional and should only be present
    /// when the key is actively being used.
    pub fn new(
        id: Id,
        master_key_id: MasterKeyId,
        plaintext_key: Option<Secret>,
        encrypted_key: impl Into<Box<[u8]>>,
        algorithm: AeadAlgorithm,
    ) -> Self {
        Self {
            id,
            master_key_id,
            encrypted_key: encrypted_key.into(),
            plaintext_key,
            algorithm,
            created_at: UtcDateTime::now(),
            last_accessed: None,
        }
    }
}

/// A unique identifier for a [`DataEncryptionKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Creates a new DEK identifier.
    ///
    /// The identifier is generated based on the provided hostname,
    /// ensuring a degree of uniqueness.
    pub fn new(hostname: &str) -> Self {
        Self(crate::utils::generate_dek_id(hostname))
    }

    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Self(s)
    }
}
