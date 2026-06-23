use thiserror::Error;
use uuid::Uuid;

use crate::domain::models::tenants::SignAlgorithm;
use crate::domain::ports::TenantRepo;
use cloud_wallet_openid4vc::oid4vci::client::CryptoSigner;

/// Errors that can occur while loading a tenant key and turning it into a
/// cryptographic signer.
#[derive(Debug, Error)]
pub enum TenantKeyError {
    /// The tenant key could not be loaded from the repository.
    #[error("tenant key lookup failed: {0}")]
    Lookup(#[from] crate::domain::models::tenants::TenantError),

    /// The key material was loaded but could not be turned into a signer.
    #[error("failed to build cryptographic signer from tenant key: {0}")]
    Signer(#[from] cloud_wallet_openid4vc::oid4vci::client::ClientError),

    /// The blocking task building the signer panicked.
    #[error("signer construction panicked: {0}")]
    Panic(#[from] tokio::task::JoinError),
}

/// Loads the tenant key material for `tenant_id` and builds a [`CryptoSigner`].
pub async fn tenant_crypto_signer(
    tenant_repo: &dyn TenantRepo,
    tenant_id: Uuid,
) -> Result<CryptoSigner, TenantKeyError> {
    let key = tenant_repo.find_key(tenant_id).await?;

    tokio::task::spawn_blocking(move || {
        let der = key.der_bytes.expose();
        match key.algorithm {
            SignAlgorithm::Ecdsa => CryptoSigner::from_ecdsa_der(der),
            SignAlgorithm::EdDsa => CryptoSigner::from_ed25519_der(der),
            SignAlgorithm::Rsa => CryptoSigner::from_rsa_der(der),
        }
    })
    .await?
    .map_err(Into::into)
}
