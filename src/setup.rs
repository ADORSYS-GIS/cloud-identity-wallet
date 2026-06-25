use std::sync::Arc;

use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::formats::mdoc::{RevocationPolicy, StaticTrustStore};
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;
use cloud_wallet_openid4vc::oid4vp::client::{Oid4vpClient, Oid4vpConfig};
use rustls_pki_types::TrustAnchor;

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::models::presentation::PresentationEngine;
use crate::domain::ports::{CredentialRepo, TenantRepo};
use crate::domain::service::Service;
use crate::outbound::{
    MemoryCredentialRepo, MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue,
};
use crate::session::SessionStore;
use crate::utils::{RootTrustStore, load_root_truststore};

/// Constructs an [`IssuanceEngine`] from configuration.
///
/// Supplies the IACA root certificates from `trust_store` and the revocation
/// policy from `config.oid4vc`.
pub fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    credential_repo: impl CredentialRepo,
    tenant_repo: impl TenantRepo,
    session_store: &S,
    trust_store: &RootTrustStore,
) -> color_eyre::Result<IssuanceEngine> {
    let client_config = Oid4vciClientConfig::new(
        config.oid4vc.client_id.clone(),
        config.oid4vc.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vc.use_system_proxy)
    // TODO : remove this later on - only for local testing
    .accept_untrusted_hosts(true);

    let client = Oid4vciClient::new(OidClient::new(client_config)?);

    // TODO: Replace with production adapters (Redis, SQL)
    let task_queue = MemoryTaskQueue::new();
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    let preferred_display_locales = config.oid4vc.preferred_display_locales.clone();

    let revocation_policy = config.oid4vc.revocation_policy;
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
    .with_iaca_trust_store(StaticTrustStore::new(trust_store.iaca_roots.clone()))
    .with_x5c_trust_anchors(trust_store.x5c_trust_anchors.clone())
    .with_revocation_policy(revocation_policy);
    Ok(engine)
}

/// Constructs a [`PresentationEngine`] from configuration.
///
/// Supplies the X5C trust anchors from `trust_store`.
pub fn build_presentation_engine(
    config: &Config,
    credential_repo: impl CredentialRepo,
    tenant_repo: impl TenantRepo,
    x5c_trust_anchors: Arc<Vec<TrustAnchor<'static>>>,
) -> color_eyre::Result<PresentationEngine> {
    // Build an OidClient to get a properly configured ClientWithMiddleware.
    // This reuses the same proxy/TLS/retry settings as the issuance flow.
    let oid_client_config = Oid4vciClientConfig::new(
        config.oid4vc.client_id.clone(),
        config.oid4vc.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vc.use_system_proxy)
    .accept_untrusted_hosts(true);

    let oid_client = OidClient::new(oid_client_config)?;

    let oid4vp_config = Oid4vpConfig {
        http_client: oid_client.http_client().clone(),
        discovery_mode: config.oid4vc.discovery_mode,
        wallet_metadata: None,
    };
    let oid4vp_client = Oid4vpClient::new(oid4vp_config);

    let engine = PresentationEngine::new(
        oid4vp_client,
        credential_repo,
        tenant_repo,
        x5c_trust_anchors,
    );
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
///
/// Loads the root truststore once from [`Config::oid4vc`] and shares it
/// across both the issuance and presentation engines.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let trust_store = load_root_truststore(config.oid4vc.root_truststore_dir.as_deref())?;

    let credential_repo = MemoryCredentialRepo::new();
    let issuance_engine = build_issuance_engine(
        config,
        credential_repo.clone(),
        tenant_repo.clone(),
        &session_store,
        &trust_store,
    )?;
    let x5c_trust_anchors = Arc::new(trust_store.x5c_trust_anchors);
    let presentation_engine = build_presentation_engine(
        config,
        credential_repo,
        tenant_repo.clone(),
        x5c_trust_anchors,
    )?;
    Ok(Service::new(
        session_store,
        tenant_repo,
        issuance_engine,
        presentation_engine,
    ))
}
