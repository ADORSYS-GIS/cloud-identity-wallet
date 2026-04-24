use std::sync::Arc;

use crate::domain::ports::TenantRepository;
use crate::issuance::AuthorizationUrlBuilder;
use crate::server::sse::SseEvent;
use crate::session::SessionStore;

#[derive(Clone)]
pub struct Service<S: SessionStore> {
    pub session: S,
    pub tenant_repo: Arc<dyn TenantRepository>,
    pub authz_url_builder: Arc<AuthorizationUrlBuilder>,
    pub sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
}

impl<S: SessionStore> Service<S> {
    /// Creates a new Service with the given session store, tenant repository, and components.
    pub fn new<R: TenantRepository>(
        session: S,
        tenant_repo: R,
        authz_url_builder: AuthorizationUrlBuilder,
        sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
    ) -> Self {
        Self {
            session,
            tenant_repo: Arc::new(tenant_repo),
            authz_url_builder: Arc::new(authz_url_builder),
            sse_broadcast,
        }
    }
}
