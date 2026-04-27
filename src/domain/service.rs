use std::sync::Arc;

use cloud_wallet_openid4vc::issuance::client::Oid4vciClient;

use crate::domain::ports::TenantRepository;
use crate::session::SessionStore;

#[derive(Clone)]
pub struct Service<S> {
    pub session: S,
    pub tenant_repo: Arc<dyn TenantRepository>,
    pub oid4vci_client: Oid4vciClient,
}

impl<S: SessionStore> Service<S>
where
    S: SessionStore,
{
    pub fn new<R: TenantRepository>(session: S, tenant_repo: R, oid4vci_client: Oid4vciClient) -> Self {
        Self {
            session,
            tenant_repo: Arc::new(tenant_repo),
            oid4vci_client,
        }
    }
}

impl<S> std::fmt::Debug for Service<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("session", &std::any::type_name::<S>())
            .field(
                "tenant_repo",
                &std::any::type_name::<dyn TenantRepository>(),
            )
            .finish()
    }
}
