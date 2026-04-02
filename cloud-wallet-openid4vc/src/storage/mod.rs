pub(crate) mod database;
pub(crate) mod memory;

pub use database::SqlRepository;
pub use memory::InMemoryRepository;

use async_trait::async_trait;
use color_eyre::eyre::Report;
use uuid::Uuid;

use crate::credential::{Credential, CredentialFormat, CredentialStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage backend error: {0}")]
    Backend(Report),

    #[error("Credential not found for id={id}, tenant_id={tenant_id}")]
    NotFound { id: Uuid, tenant_id: Uuid },

    #[error("Invalid stored credential data: {0}")]
    InvalidData(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Storage error: {0}")]
    Other(String),
}

impl From<cloud_wallet_kms::Error> for Error {
    fn from(error: cloud_wallet_kms::Error) -> Self {
        Self::Encryption(error.to_string())
    }
}

#[async_trait]
pub trait CredentialRepository: Send + Sync + 'static {
    async fn upsert(&self, credential: Credential) -> Result<uuid::Uuid>;

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential>;

    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>>;

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    pub tenant_id: Option<Uuid>,
    pub credential_types: Option<Vec<String>>,
    pub status: Option<CredentialStatus>,
    pub format: Option<CredentialFormat>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub exclude_expired: bool,
}

impl CredentialFilter {
    pub fn matches(&self, credential: &Credential) -> bool {
        if let Some(tenant_id) = self.tenant_id {
            if credential.tenant_id != tenant_id {
                return false;
            }
        }
        if let Some(status) = self.status {
            if credential.status != status {
                return false;
            }
        }
        if let Some(format) = self.format {
            if credential.format != format {
                return false;
            }
        }
        if let Some(issuer) = &self.issuer {
            if credential.issuer != *issuer {
                return false;
            }
        }
        if let Some(subject) = &self.subject {
            if credential.subject.as_deref() != Some(subject.as_str()) {
                return false;
            }
        }
        if let Some(types) = &self.credential_types {
            if &credential.credential_types != types {
                return false;
            }
        }
        if self.exclude_expired {
            if let Some(valid_until) = credential.valid_until {
                if valid_until <= time::UtcDateTime::now() {
                    return false;
                }
            }
        }
        true
    }
}
