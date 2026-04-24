use super::ports::{SessionRepository, TenantRepository};
use std::sync::Arc;

use crate::issuance::AuthorizationUrlBuilder;
use crate::server::sse::SseEvent;

pub struct Service {
    pub tenant_repo: Arc<dyn TenantRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub authz_url_builder: Arc<AuthorizationUrlBuilder>,
    pub sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
}

impl Service {
    /// Creates a new Service with the given repositories and components.
    pub fn new<T: TenantRepository, S: SessionRepository>(
        tenant_repo: T,
        session_repo: S,
        authz_url_builder: AuthorizationUrlBuilder,
        sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
    ) -> Self {
        Self {
            tenant_repo: Arc::new(tenant_repo),
            session_repo: Arc::new(session_repo),
            authz_url_builder: Arc::new(authz_url_builder),
            sse_broadcast,
        }
    }
}
