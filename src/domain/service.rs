use std::sync::Arc;

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

impl<S> std::fmt::Debug for Service<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("session", &std::any::type_name::<S>())
            .field("tenant_repo", &std::any::type_name::<dyn TenantRepo>())
            .field("issuance_engine", &self.issuance_engine)
            .finish()
    }
}
