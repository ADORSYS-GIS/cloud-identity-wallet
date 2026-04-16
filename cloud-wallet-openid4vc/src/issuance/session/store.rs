use async_trait::async_trait;
use uuid::Uuid;

use crate::errors::Result;
use crate::issuance::session::IssuanceSession;

#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn create(&self, session: IssuanceSession) -> Result<()>;
    async fn get(&self, id: &str, tenant_id: Uuid) -> Result<Option<IssuanceSession>>;
    async fn update(&self, session: IssuanceSession) -> Result<()>;
    async fn delete(&self, id: &str) -> Result<()>;
}
