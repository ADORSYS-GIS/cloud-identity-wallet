use crate::AeadAlgorithm;

/// Represents the metadata of a Master Key.
///
/// This struct holds information about a Master Key, but not the key material itself, which should
/// be managed by a secure key management system (KMS). Master Keys are used to encrypt and decrypt
/// Data Encryption Keys (DEKs).
#[derive(Debug, Clone)]
pub struct Metadata {
    /// The unique identifier for this master key.
    pub id: Id,

    /// The AEAD algorithm used for cryptographic operations with this key.
    pub algorithm: AeadAlgorithm,

    /// The timestamp of when this master key was created.
    pub created_at: time::UtcDateTime,
}

impl Metadata {
    /// Creates new metadata for a master key.
    pub fn new(id: Id, algorithm: AeadAlgorithm) -> Self {
        Self {
            id,
            algorithm,
            created_at: time::UtcDateTime::now(),
        }
    }
}

/// A unique identifier for a Master Key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(String);

impl Id {
    /// Creates a new master key ID.
    ///
    /// The ID is generated based on the provided hostname, which is useful
    /// for creating unique keys in a distributed environment.
    pub fn new(hostname: &str) -> Self {
        Self(crate::utils::generate_mk_id(hostname))
    }

    /// Returns the ID as a string slice for easy access.
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
