use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::formats::mdoc::{RevocationPolicy, StaticTrustStore};
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::ports::TenantRepo;
use crate::domain::service::Service;
use crate::outbound::{
    MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
};
use crate::session::SessionStore;
use crate::utils::load_iaca_roots;

/// Constructs an [`IssuanceEngine`] from configuration.
///
/// Loads IACA roots from [`crate::config::Oid4vciConfig`].  Returns an error if any
/// configured root path is unreadable or is a PEM file with no certificates.
/// Logs a `WARN` at startup if no roots are loaded — the resulting store is
/// fail-closed and all mso_mdoc issuances will be rejected.
pub fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    tenant_repo: impl TenantRepo,
    session_store: &S,
) -> color_eyre::Result<IssuanceEngine> {
    let client_config = Oid4vciClientConfig::new(
        config.oid4vci.client_id.clone(),
        config.oid4vci.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vci.use_system_proxy)
    // TODO : remove this later on - only for local testing
    .accept_untrusted_hosts(true);

    let client = Oid4vciClient::new(OidClient::new(client_config)?);

    // TODO: Replace with production adapters (Redis, SQL)
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    let credential_repo = MemoryCredentialRepo::new();
    let preferred_display_locales = config.oid4vci.preferred_display_locales.clone();

    let iaca_roots = load_iaca_roots(&config.oid4vci.iaca_root_paths)?;
    if iaca_roots.is_empty() {
        tracing::warn!(
            "mdoc IACA trust store is empty: all mso_mdoc credential issuances will be rejected"
        );
    }

    // Use revocation policy from config, defaulting to SoftFail if not specified.
    let revocation_policy = config.oid4vci.revocation_policy;
    if revocation_policy != RevocationPolicy::default() {
        tracing::info!(
            policy = ?revocation_policy,
            "using non-default revocation policy from configuration"
        );
    }

    let engine = IssuanceEngine::new(
        client,
        task_queue,
        publisher,
        subscriber,
        credential_repo,
        tenant_repo,
        session_store,
        preferred_display_locales,
    )
    .with_iaca_trust_store(StaticTrustStore::new(iaca_roots))
    .with_revocation_policy(revocation_policy);
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let engine = build_issuance_engine(config, tenant_repo.clone(), &session_store)?;
    Ok(Service::new(session_store, tenant_repo, engine))
}
