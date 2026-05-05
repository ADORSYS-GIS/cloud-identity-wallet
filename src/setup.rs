use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::domain::service::Service;
use crate::outbound::{
    MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
};
use crate::session::SessionStore;

pub fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    tenant_repo: impl TenantRepo,
    session_store: &S,
) -> color_eyre::Result<(IssuanceEngine, MemoryEventSubscriber)> {
    let client_config = Oid4vciClientConfig::new(
        config.oid4vci.client_id.clone(),
        config.oid4vci.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vci.use_system_proxy)
    // TODO : remove this later on - only for local testing
    .accept_untrusted_hosts(true);
    let client = Oid4vciClient::new(client_config)?;

    // TODO: Replace with production adapters (Redis, SQL)
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let event_subscriber = MemoryEventSubscriber::new(&publisher);
    let credential_repo = MemoryCredentialRepo::new();

    let engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        credential_repo,
        tenant_repo,
        session_store,
    );
    Ok((engine, event_subscriber))
}

/// Build a fully wired [`Service`] ready for use in the server.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let (engine, event_subscriber) =
        build_issuance_engine(config, tenant_repo.clone(), &session_store)?;
    Ok(Service::new(
        session_store,
        tenant_repo,
        engine,
        event_subscriber,
    ))
}
