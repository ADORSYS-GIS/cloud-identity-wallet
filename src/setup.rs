use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::formats::mdoc::StaticTrustStore;
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;
use cloud_wallet_openid4vc::oid4vp::client::Oid4vpClient;

use crate::config::Config;
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::models::presentation::PresentationEngine;
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
    .with_iaca_trust_store(StaticTrustStore::new(iaca_roots));
    Ok(engine)
}

/// Constructs a [`PresentationEngine`] from configuration.
///
/// Reuses the same IACA trust anchors for X.509-based verifier key resolution.
/// The HTTP client is constructed via [`OidClient`] to share the same TLS
/// and retry middleware configuration as the issuance flow.
pub fn build_presentation_engine(
    config: &Config,
    credential_repo: impl crate::domain::ports::CredentialRepo,
    tenant_repo: impl TenantRepo,
) -> color_eyre::Result<PresentationEngine> {
    // Build an OidClient to get a properly configured ClientWithMiddleware.
    // This reuses the same proxy/TLS/retry settings as the issuance flow.
    let oid_client_config = Oid4vciClientConfig::new(
        config.oid4vci.client_id.clone(),
        config.oid4vci.redirect_uri.clone(),
    )
    .use_system_proxy(config.oid4vci.use_system_proxy)
    .accept_untrusted_hosts(true);

    let oid_client = OidClient::new(oid_client_config)?;

    let oid4vp_config = cloud_wallet_openid4vc::oid4vp::client::Oid4vpConfig {
        http_client: oid_client.http_client().clone(),
        discovery_mode: cloud_wallet_openid4vc::oid4vp::request_object::DiscoveryMode::Dynamic,
        wallet_metadata: None,
    };
    let oid4vp_client = Oid4vpClient::new(oid4vp_config);

    // Load IACA roots for X.509 verifier key resolution (raw DER bytes)
    let x509_trust_anchor_der = load_iaca_roots(&config.oid4vci.iaca_root_paths)?;
    if x509_trust_anchor_der.is_empty() {
        tracing::warn!(
            "X.509 verifier trust store is empty: all x509_san_dns / x509_hash \
             verifier key resolutions will fail"
        );
    }

    let engine = PresentationEngine::new(
        oid4vp_client,
        credential_repo,
        tenant_repo,
        x509_trust_anchor_der,
    );
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
pub fn build_service<S: SessionStore + Clone>(
    session_store: S,
    tenant_repo: impl TenantRepo + Clone,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let issuance_engine = build_issuance_engine(config, tenant_repo.clone(), &session_store)?;
    let presentation_engine =
        build_presentation_engine(config, MemoryCredentialRepo::new(), tenant_repo.clone())?;
    Ok(Service::new(
        session_store,
        tenant_repo,
        issuance_engine,
        presentation_engine,
    ))
}
