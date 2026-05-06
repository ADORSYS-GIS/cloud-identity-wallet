use cloud_wallet_openid4vc::issuance::client::{Config as Oid4vciClientConfig, Oid4vciClient};

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::domain::service::Service;
use crate::outbound::{MemoryCredentialRepo, MemoryEventPublisher, MemoryTaskQueue};
use crate::session::SessionStore;

pub fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    tenant_repo: impl TenantRepo,
    session_store: &S,
    credential_repo: MemoryCredentialRepo,
) -> color_eyre::Result<IssuanceEngine> {
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

    let engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        credential_repo,
        tenant_repo,
        session_store,
    );
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let credential_repo = MemoryCredentialRepo::new();
    let engine = build_issuance_engine(
        config,
        tenant_repo.clone(),
        &session_store,
        credential_repo.clone(),
    )?;
    Ok(Service::new(
        session_store,
        tenant_repo,
        engine,
        credential_repo,
    ))
}

/// Build a fully wired [`Service`] and return the shared credential repository.
///
/// The caller receives a clone of the `MemoryCredentialRepo` that backs the
/// running service, enabling tests to pre-populate credentials and assert on
/// stored state without going through the HTTP layer.
pub fn build_service_with_repo<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<(Service<S>, MemoryCredentialRepo)> {
    let credential_repo = MemoryCredentialRepo::new();
    let engine = build_issuance_engine(
        config,
        tenant_repo.clone(),
        &session_store,
        credential_repo.clone(),
    )?;
    let service = Service::new(session_store, tenant_repo, engine, credential_repo.clone());
    Ok((service, credential_repo))
}
