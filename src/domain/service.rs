use std::sync::Arc;

use crate::domain::ports::TenantRepository;
use crate::server::sse::SseEvent;
use crate::session::SessionStore;
use cloud_wallet_openid4vc::issuance::client::{Config, Oid4vciClient};

#[derive(Clone)]
pub struct Service<S: SessionStore> {
    pub session: S,
    pub tenant_repo: Arc<dyn TenantRepository>,
    pub oid4vci_client: Arc<Oid4vciClient>,
    pub sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
}

impl<S: SessionStore> Service<S> {
    /// Creates a new Service with the given session store, tenant repository, and components.
    pub fn new<R: TenantRepository>(
        session: S,
        tenant_repo: R,
        oid4vci_client: Oid4vciClient,
        sse_broadcast: tokio::sync::broadcast::Sender<SseEvent>,
    ) -> Self {
        Self {
            session,
            tenant_repo: Arc::new(tenant_repo),
            oid4vci_client: Arc::new(oid4vci_client),
            sse_broadcast,
        }
    }
}

/// Creates an OID4VCI client with the given configuration.
pub fn create_oid4vci_client(
    client_id: String,
    redirect_uri: url::Url,
) -> Result<Oid4vciClient, String> {
    let config = Config::new(client_id, redirect_uri);
    Oid4vciClient::new(config).map_err(|e| format!("Failed to create OID4VCI client: {e}"))
}
