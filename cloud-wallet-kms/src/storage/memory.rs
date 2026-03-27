use dashmap::DashMap;
use std::sync::Arc;

use crate::key::dek::{DataEncryptionKey, Id as DekId};
use crate::storage::Storage;

/// An in-memory `Storage` backend for DEKs.
///
/// Intended for testing and development scenarios
/// where data persistence is not required.
#[derive(Debug, Clone, Default)]
pub struct InMemoryBackend {
    deks: Arc<DashMap<DekId, DataEncryptionKey>>,
}

impl InMemoryBackend {
    /// Creates a new `InMemoryBackend`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Storage for InMemoryBackend {
    async fn upsert_dek(&self, dek: &DataEncryptionKey) -> crate::Result<()> {
        self.deks.insert(dek.id.clone(), dek.clone());
        Ok(())
    }

    async fn get_dek(&self, id: &DekId) -> crate::Result<Option<DataEncryptionKey>> {
        match self.deks.get(id).map(|v| v.value().clone()) {
            Some(mut entry) => {
                let now = time::UtcDateTime::now();
                entry.last_accessed = Some(now);
                self.deks.insert(id.clone(), entry.clone());
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }
}
