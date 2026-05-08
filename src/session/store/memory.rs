use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, Entry};

use crate::session::{Id, Result, SessionStore};
use serde::de::DeserializeOwned;

const DEFAULT_TTL: Duration = Duration::from_mins(15);

#[derive(Debug, Clone)]
struct SessionEntry {
    value: Box<[u8]>,
    expires_at: Instant,
}

/// An in-memory session manager.
///
/// Expired entries are cleaned up lazily during reads/writes on the same key.
/// Because of this behavior, it is suitable for testing and development purposes only.
#[derive(Debug, Clone)]
pub struct MemorySession {
    entries: Arc<DashMap<Box<[u8]>, SessionEntry>>,
    ttl: Duration,
}

impl Default for MemorySession {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl MemorySession {
    /// Creates a new in-memory session manager with the provided TTL.
    pub fn new(ttl: Duration) -> Self {
        assert!(
            ttl > Duration::ZERO,
            "session TTL must be greater than zero"
        );
        Self {
            entries: Arc::default(),
            ttl,
        }
    }

    fn make_entry(&self, value: &[u8]) -> SessionEntry {
        SessionEntry {
            value: value.into(),
            expires_at: Instant::now() + self.ttl,
        }
    }

    fn is_expired(entry: &SessionEntry) -> bool {
        Instant::now() >= entry.expires_at
    }
}

#[async_trait::async_trait]
impl SessionStore for MemorySession {
    async fn upsert<K, V>(&self, key: K, value: &V) -> Result<()>
    where
        K: Into<Id> + Send + Sync,
        V: serde::Serialize + Send + Sync,
    {
        let key = key.into();
        let value_bytes = serde_json::to_vec(value)?;
        let key_bytes: Box<[u8]> = key.as_bytes().into();

        match self.entries.entry(key_bytes) {
            Entry::Occupied(mut occupied) => {
                if Self::is_expired(occupied.get()) {
                    // Entry is expired, replace it atomically
                    occupied.insert(self.make_entry(&value_bytes));
                } else {
                    // Update in place without refreshing TTL
                    occupied.get_mut().value = value_bytes.into_boxed_slice();
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(self.make_entry(&value_bytes));
            }
        }
        Ok(())
    }

    async fn get<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: DeserializeOwned + Send + Sync,
    {
        let key = key.into();
        if let Some(entry) = self.entries.get(key.as_bytes()) {
            if Self::is_expired(&entry) {
                drop(entry);
                self.entries.remove(key.as_bytes());
                return Ok(None);
            }
            let item: V = serde_json::from_slice(&entry.value)?;
            return Ok(Some(item));
        }
        Ok(None)
    }

    async fn exists<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<bool> {
        let key = key.into();
        if let Some(entry) = self.entries.get(key.as_bytes()) {
            if Self::is_expired(&entry) {
                drop(entry);
                self.entries.remove(key.as_bytes());
                return Ok(false);
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn consume<K, V>(&self, key: K) -> Result<Option<V>>
    where
        K: Into<Id> + Send + Sync,
        V: DeserializeOwned + Send + Sync,
    {
        let key = key.into();
        match self.entries.remove(key.as_bytes()) {
            Some((_, entry)) if !Self::is_expired(&entry) => {
                let item: V = serde_json::from_slice(&entry.value)?;
                Ok(Some(item))
            }
            Some(_) | None => Ok(None),
        }
    }

    async fn remove<K: Into<Id> + Send + Sync>(&self, key: K) -> Result<()> {
        let key = key.into();
        self.entries.remove(key.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn memory_roundtrip_and_remove() {
        let manager = MemorySession::new(Duration::from_secs(5));
        let key = "session-key";

        manager.upsert(key, &b"value".to_vec()).await.unwrap();
        assert!(manager.exists(key).await.unwrap());
        let val: Option<Vec<u8>> = manager.get(key).await.unwrap();
        assert_eq!(val, Some(b"value".to_vec()));

        manager.remove(key).await.unwrap();
        assert!(!manager.exists(key).await.unwrap());
        let val: Option<Vec<u8>> = manager.get(key).await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn memory_entry_expires() {
        let manager = MemorySession::new(Duration::from_millis(80));
        let key = "expiring";
        manager.upsert(key, &b"value".to_vec()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(!manager.exists(key).await.unwrap());
        let val: Option<Vec<u8>> = manager.get(key).await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn memory_upsert_does_not_extend_ttl() {
        let manager = MemorySession::new(Duration::from_millis(120));
        let key = "ttl-no-refresh";

        manager.upsert(key, &b"v1".to_vec()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(90)).await;
        manager.upsert(key, &b"v2".to_vec()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(40)).await;
        let val: Option<Vec<u8>> = manager.get(key).await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn memory_consume_is_one_time() {
        let manager = MemorySession::new(Duration::from_secs(1));
        let key = "consume-once";
        manager.upsert(key, &b"value".to_vec()).await.unwrap();

        let val_bytes: Option<Vec<u8>> = manager.consume(key).await.unwrap();
        assert_eq!(val_bytes, Some(b"value".to_vec()));

        let val: Option<Vec<u8>> = manager.consume(key).await.unwrap();
        assert_eq!(val, None);
        let val: Option<Vec<u8>> = manager.get(key).await.unwrap();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn memory_consume_is_atomic_for_concurrent_callers() {
        let manager = Arc::new(MemorySession::new(Duration::from_secs(2)));
        let key = "race-consume";
        manager.upsert(key, &b"value".to_vec()).await.unwrap();

        let callers = 24usize;
        let barrier = Arc::new(Barrier::new(callers));
        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(callers);

        for _ in 0..callers {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            let success_count = Arc::clone(&success_count);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let val: Option<Vec<u8>> = manager.consume(key).await.unwrap();
                if val.is_some() {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(success_count.load(Ordering::Relaxed), 1);
    }
}
