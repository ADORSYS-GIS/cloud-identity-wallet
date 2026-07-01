use std::sync::Arc;
#[cfg(feature = "sqlx")]
use std::time::Duration;

use cloud_wallet_openid4vc::core::client::{Config as Oid4vciClientConfig, OidClient};
use cloud_wallet_openid4vc::formats::mdoc::{RevocationPolicy, StaticTrustStore};
use cloud_wallet_openid4vc::oid4vci::client::Oid4vciClient;
use cloud_wallet_openid4vc::oid4vp::client::{Oid4vpClient, Oid4vpConfig};
use rustls_pki_types::TrustAnchor;
#[cfg(feature = "sqlx")]
use secrecy::ExposeSecret as _;
#[cfg(feature = "sqlx")]
use sqlx::any::AnyPoolOptions;

use crate::config::{Backend, Config, KmsProviderKind};
use crate::domain::models::issuance::IssuanceEngine;
use crate::domain::models::presentation::PresentationEngine;
use crate::domain::ports::{
    CredentialRepo, IssuanceEventPublisher, IssuanceEventSubscriber, IssuanceTaskQueue, TenantRepo,
};
use crate::domain::service::Service;
use crate::outbound::{MemoryEventPublisher, MemoryEventSubscriber, MemoryTaskQueue};
use crate::session::SessionStore;
use crate::utils::{RootTrustStore, load_root_truststore};

/// Constructs an [`IssuanceEngine`] from configuration.
///
/// Supplies the IACA root certificates from `trust_store` and the revocation
/// policy from `config.oid4vc`.
pub async fn build_issuance_engine<S: SessionStore + Clone>(
    config: &Config,
    credential_repo: Arc<dyn CredentialRepo>,
    tenant_repo: Arc<dyn TenantRepo>,
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

    let (task_queue, publisher, subscriber) = build_issuance_infrastructure(config).await?;
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
        config.oid4vc.preferred_display_locales.clone(),
    );
    Ok(engine)
}

/// Build a fully wired [`Service`] ready for use in the server.
pub async fn build_service<S: SessionStore + Clone>(
    session_store: S,
    config: &Config,
) -> color_eyre::Result<Service<S>> {
    let trust_store = Arc::new(load_root_truststore(
        config.oid4vc.root_truststore_dir.as_deref(),
    )?);

    let Repositories {
        credential_repo,
        tenant_repo,
    } = build_repositories(config).await?;

    let x5c_trust_anchors = Arc::new(trust_store.x5c_trust_anchors.clone());
    let issuance_engine = build_issuance_engine(
        config,
        credential_repo.clone(),
        tenant_repo.clone(),
        &session_store,
        &trust_store,
    )
    .await?;
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

struct Repositories {
    credential_repo: Arc<dyn CredentialRepo>,
    tenant_repo: Arc<dyn TenantRepo>,
}

async fn build_repositories(config: &Config) -> color_eyre::Result<Repositories> {
    match config.backend {
        Backend::Memory => build_memory_repositories(config).await,
        Backend::MySql | Backend::Postgres | Backend::Sqlite => {
            build_sql_repositories(config).await
        }
    }
}

async fn build_memory_repositories(config: &Config) -> color_eyre::Result<Repositories> {
    match config.kms.provider {
        KmsProviderKind::Local => build_memory_repositories_with_local_kms().await,
        KmsProviderKind::Aws => build_memory_repositories_with_aws_kms(config).await,
    }
}

#[cfg(all(feature = "memory", feature = "local-kms"))]
async fn build_memory_repositories_with_local_kms() -> color_eyre::Result<Repositories> {
    use crate::outbound::{MemoryCredentialRepo, MemoryTenantRepo, TenantKeyAlg};
    use cloud_wallet_kms::provider::LocalProvider;

    Ok(Repositories {
        credential_repo: Arc::new(MemoryCredentialRepo::with_cipher(LocalProvider::new())),
        tenant_repo: Arc::new(MemoryTenantRepo::with_cipher(
            TenantKeyAlg::default(),
            LocalProvider::new(),
        )),
    })
}

#[cfg(not(all(feature = "memory", feature = "local-kms")))]
async fn build_memory_repositories_with_local_kms() -> color_eyre::Result<Repositories> {
    color_eyre::eyre::bail!(
        "APP_BACKEND=memory with APP_KMS__PROVIDER=local requires the `memory,local-kms` Cargo features"
    )
}

#[cfg(all(feature = "aws-kms", feature = "memory"))]
async fn build_memory_repositories_with_aws_kms(
    config: &Config,
) -> color_eyre::Result<Repositories> {
    use crate::outbound::{MemoryCredentialRepo, MemoryTenantRepo, TenantKeyAlg};
    use cloud_wallet_kms::provider::AwsProvider;
    use cloud_wallet_kms::storage::InMemoryBackend;

    let aws_config = load_aws_config(config).await;
    let hostname = config.server.host.clone();
    Ok(Repositories {
        credential_repo: Arc::new(MemoryCredentialRepo::with_cipher(AwsProvider::new(
            &aws_config,
            &hostname,
            InMemoryBackend::new(),
        ))),
        tenant_repo: Arc::new(MemoryTenantRepo::with_cipher(
            TenantKeyAlg::default(),
            AwsProvider::new(&aws_config, &hostname, InMemoryBackend::new()),
        )),
    })
}

#[cfg(not(all(feature = "aws-kms", feature = "memory")))]
async fn build_memory_repositories_with_aws_kms(
    _config: &Config,
) -> color_eyre::Result<Repositories> {
    color_eyre::eyre::bail!(
        "APP_KMS__PROVIDER=aws with APP_BACKEND=memory requires the `aws-kms,memory` Cargo features"
    )
}

#[cfg(feature = "sqlx")]
async fn build_sql_repositories(config: &Config) -> color_eyre::Result<Repositories> {
    ensure_sql_backend_feature(config.backend)?;
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(100)
        .idle_timeout(Duration::from_mins(5))
        .max_lifetime(Duration::from_mins(30))
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(config.database.url.expose_secret())?;

    match config.kms.provider {
        KmsProviderKind::Local => build_sql_repositories_with_local_kms(pool).await,
        KmsProviderKind::Aws => build_sql_repositories_with_aws_kms(config, pool).await,
    }
}

#[cfg(not(feature = "sqlx"))]
async fn build_sql_repositories(_config: &Config) -> color_eyre::Result<Repositories> {
    color_eyre::eyre::bail!(
        "SQL backends require one of the `mysql`, `postgres`, or `sqlite` Cargo features"
    )
}

#[cfg(all(feature = "sqlx", feature = "local-kms"))]
async fn build_sql_repositories_with_local_kms(
    pool: sqlx::AnyPool,
) -> color_eyre::Result<Repositories> {
    use crate::outbound::{SqlCredentialRepo, SqlTenantRepo, TenantKeyAlg};
    use cloud_wallet_kms::provider::LocalProvider;
    use cloud_wallet_kms::storage::SqlxBackend;

    let credential_kms_storage = SqlxBackend::new(pool.clone());
    credential_kms_storage.init_schema().await?;
    let credential_repo = SqlCredentialRepo::with_cipher(
        pool.clone(),
        LocalProvider::with_storage(credential_kms_storage),
    );
    credential_repo.init_schema().await?;

    let tenant_kms_storage = SqlxBackend::new(pool.clone());
    tenant_kms_storage.init_schema().await?;
    let tenant_repo = SqlTenantRepo::new(
        pool,
        TenantKeyAlg::default(),
        LocalProvider::with_storage(tenant_kms_storage),
    );
    tenant_repo.init_schema().await?;

    Ok(Repositories {
        credential_repo: Arc::new(credential_repo),
        tenant_repo: Arc::new(tenant_repo),
    })
}

#[cfg(all(feature = "sqlx", not(feature = "local-kms")))]
async fn build_sql_repositories_with_local_kms(
    _pool: sqlx::AnyPool,
) -> color_eyre::Result<Repositories> {
    color_eyre::eyre::bail!("APP_KMS__PROVIDER=local requires the `local-kms` Cargo feature")
}

#[cfg(all(feature = "sqlx", feature = "aws-kms"))]
async fn build_sql_repositories_with_aws_kms(
    config: &Config,
    pool: sqlx::AnyPool,
) -> color_eyre::Result<Repositories> {
    use crate::outbound::{SqlCredentialRepo, SqlTenantRepo, TenantKeyAlg};
    use cloud_wallet_kms::provider::AwsProvider;
    use cloud_wallet_kms::storage::SqlxBackend;

    let aws_config = load_aws_config(config).await;
    let hostname = config.server.host.clone();
    let credential_kms_storage = SqlxBackend::new(pool.clone());
    credential_kms_storage.init_schema().await?;
    let credential_repo = SqlCredentialRepo::with_cipher(
        pool.clone(),
        AwsProvider::new(&aws_config, &hostname, credential_kms_storage),
    );
    credential_repo.init_schema().await?;

    let tenant_kms_storage = SqlxBackend::new(pool.clone());
    tenant_kms_storage.init_schema().await?;
    let tenant_repo = SqlTenantRepo::new(
        pool,
        TenantKeyAlg::default(),
        AwsProvider::new(&aws_config, &hostname, tenant_kms_storage),
    );
    tenant_repo.init_schema().await?;

    Ok(Repositories {
        credential_repo: Arc::new(credential_repo),
        tenant_repo: Arc::new(tenant_repo),
    })
}

#[cfg(all(feature = "sqlx", not(feature = "aws-kms")))]
async fn build_sql_repositories_with_aws_kms(
    _config: &Config,
    _pool: sqlx::AnyPool,
) -> color_eyre::Result<Repositories> {
    color_eyre::eyre::bail!("APP_KMS__PROVIDER=aws requires the `aws-kms` Cargo feature")
}

async fn build_issuance_infrastructure(
    config: &Config,
) -> color_eyre::Result<(
    Arc<dyn IssuanceTaskQueue>,
    Arc<dyn IssuanceEventPublisher>,
    Arc<dyn IssuanceEventSubscriber>,
)> {
    if cfg!(feature = "redis") && !matches!(config.backend, Backend::Memory) {
        return build_redis_issuance_infrastructure(config).await;
    }

    Ok(build_memory_issuance_infrastructure())
}

fn build_memory_issuance_infrastructure() -> (
    Arc<dyn IssuanceTaskQueue>,
    Arc<dyn IssuanceEventPublisher>,
    Arc<dyn IssuanceEventSubscriber>,
) {
    let publisher = MemoryEventPublisher::new(128);
    let subscriber = MemoryEventSubscriber::new(&publisher);
    (
        Arc::new(MemoryTaskQueue::new()),
        Arc::new(publisher),
        Arc::new(subscriber),
    )
}

#[cfg(feature = "redis")]
async fn build_redis_issuance_infrastructure(
    config: &Config,
) -> color_eyre::Result<(
    Arc<dyn IssuanceTaskQueue>,
    Arc<dyn IssuanceEventPublisher>,
    Arc<dyn IssuanceEventSubscriber>,
)> {
    use crate::outbound::{RedisEventPublisher, RedisEventSubscriber, RedisTaskQueue};

    let (conn, push_rx) = config.redis.start().await?;
    Ok((
        Arc::new(RedisTaskQueue::new(conn.clone())),
        Arc::new(RedisEventPublisher::new(conn.clone())),
        Arc::new(RedisEventSubscriber::new(conn, push_rx)),
    ))
}

#[cfg(not(feature = "redis"))]
async fn build_redis_issuance_infrastructure(
    _config: &Config,
) -> color_eyre::Result<(
    Arc<dyn IssuanceTaskQueue>,
    Arc<dyn IssuanceEventPublisher>,
    Arc<dyn IssuanceEventSubscriber>,
)> {
    color_eyre::eyre::bail!("Redis issuance infrastructure requires the `redis` Cargo feature")
}

#[cfg(feature = "sqlx")]
fn ensure_sql_backend_feature(backend: Backend) -> color_eyre::Result<()> {
    match backend {
        Backend::Memory => Ok(()),
        Backend::MySql if cfg!(feature = "mysql") => Ok(()),
        Backend::Postgres if cfg!(feature = "postgres") => Ok(()),
        Backend::Sqlite if cfg!(feature = "sqlite") => Ok(()),
        Backend::MySql => {
            color_eyre::eyre::bail!("APP_BACKEND=mysql requires the `mysql` Cargo feature")
        }
        Backend::Postgres => {
            color_eyre::eyre::bail!("APP_BACKEND=postgres requires the `postgres` Cargo feature")
        }
        Backend::Sqlite => {
            color_eyre::eyre::bail!("APP_BACKEND=sqlite requires the `sqlite` Cargo feature")
        }
    }
}

#[cfg(feature = "aws-kms")]
async fn load_aws_config(config: &Config) -> aws_config::SdkConfig {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = &config.kms.aws_region {
        loader = loader.region(aws_config::Region::new(region.clone()));
    }
    loader.load().await
}
