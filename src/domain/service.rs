use std::sync::Arc;

use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::{IssuanceEventSubscriber, TenantRepo};
use crate::session::SessionStore;

#[derive(Clone)]
pub struct Service<S> {
    pub session: S,
    pub tenant_repo: Arc<dyn TenantRepo>,
    pub issuance_engine: IssuanceEngine,
    pub event_subscriber: Arc<dyn IssuanceEventSubscriber>,
}

impl<S: SessionStore + Clone> Service<S> {
    pub fn new<R, E>(
        session: S,
        tenant_repo: R,
        issuance_engine: IssuanceEngine,
        event_subscriber: E,
    ) -> Self
    where
        R: TenantRepo,
        E: IssuanceEventSubscriber,
    {
        Self {
            session,
            tenant_repo: Arc::new(tenant_repo),
            issuance_engine,
            event_subscriber: Arc::new(event_subscriber),
        }
    }
}

impl<S> std::fmt::Debug for Service<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("session", &std::any::type_name::<S>())
            .field("tenant_repo", &std::any::type_name::<dyn TenantRepo>())
            .field("issuance_engine", &self.issuance_engine)
            .field(
                "event_subscriber",
                &std::any::type_name::<dyn IssuanceEventSubscriber>(),
            )
            .finish()
    }
}
