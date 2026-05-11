use std::sync::Arc;

use uuid::Uuid;

use crate::domain::models::credential::CredentialError;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::session::SessionStore;

#[derive(Clone)]
pub struct Service<S> {
    pub session: S,
    pub tenant_repo: Arc<dyn TenantRepo>,
    pub issuance_engine: IssuanceEngine,
}

impl<S: SessionStore + Clone> Service<S> {
    pub fn new<R: TenantRepo>(session: S, tenant_repo: R, issuance_engine: IssuanceEngine) -> Self {
        Self {
            session,
            tenant_repo: Arc::new(tenant_repo),
            issuance_engine,
        }
    }
}

impl<S: SessionStore> Service<S> {
    /// Deletes a credential owned by the authenticated tenant.
    ///
    /// Scopes the deletion to `credential_id` + `tenant_id` so that one tenant
    /// can never remove another tenant's credential.
    pub async fn delete_credential(
        &self,
        credential_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), CredentialError> {
        self.issuance_engine
            .credential_repo
            .delete(credential_id, tenant_id)
            .await
    }
}

impl<S> std::fmt::Debug for Service<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("session", &std::any::type_name::<S>())
            .field("tenant_repo", &std::any::type_name::<dyn TenantRepo>())
            .field("issuance_engine", &self.issuance_engine)
            .finish()
    }
}
