mod data;
mod error;
mod store;
mod utils;

pub use data::*;
pub use error::Error as SessionError;
pub use store::{MemorySession, RedisSession};
pub use utils::generate_session_id;

pub type Result<T> = std::result::Result<T, SessionError>;

/// A session store interface used to manage the lifecycle of sessions.
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Inserts or updates a session in the store.
    async fn upsert<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Into<Id> + Send + Sync,
        V: serde::Serialize + Send + Sync;

    /// Retrieves a session from the store.
    async fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync;

    /// Checks if a session exists in the store.
    async fn exists<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<bool>;

    /// Atomically retrieves and removes a session from the store.
    ///
    /// This method provides one-time consume semantics.
    async fn consume<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: serde::de::DeserializeOwned + Send + Sync;

    /// Removes a session from the store.
    async fn remove<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<()>;
}

/// ID type for sessions
///
/// Wraps a vector of bytes
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Id(Box<[u8]>);

impl Id {
    /// Creates a new session ID.
    pub fn new<T: Into<Box<[u8]>>>(value: T) -> Self {
        Self(value.into())
    }

    /// Get the inner bytes of the ID
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Id {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Id {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a [u8]> for Id {
    fn from(value: &'a [u8]) -> Self {
        Self(value.into())
    }
}

impl<const N: usize> From<&[u8; N]> for Id {
    fn from(value: &[u8; N]) -> Self {
        Self(value.as_slice().into())
    }
}

impl From<Vec<u8>> for Id {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().into())
    }
}

impl From<String> for Id {
    fn from(value: String) -> Self {
        Self(value.into_bytes().into())
    }
}
