/*
   Module `outbound` contains the canonical implementations of the ports traits
   by which external modules interact with the domain.
*/

mod credential;
mod tenant;

pub use credential::{MemoryCredentialRepo, SqlCredentialRepo};
pub use tenant::{MemoryTenantRepo, SqlTenantRepo};

mod cipher {
    use cloud_wallet_kms::{self as kms, provider::Provider};
    use std::sync::Arc;

    /// A dyn-compatible internal cipher abstraction.
    #[async_trait::async_trait]
    pub(super) trait Cipher: Send + Sync + 'static {
        async fn encrypt(&self, aad: &[u8], data: &mut Vec<u8>) -> cloud_wallet_kms::Result<()>;

        async fn decrypt<'a>(
            &self,
            aad: &[u8],
            data: &'a mut [u8],
        ) -> cloud_wallet_kms::Result<&'a [u8]>;
    }

    /// Newtype that wraps any KmsProvider and implements Cipher.
    struct KmsBridge<K>(K);

    #[async_trait::async_trait]
    impl<K: Provider + Send + Sync + 'static> Cipher for KmsBridge<K> {
        async fn encrypt(&self, aad: &[u8], data: &mut Vec<u8>) -> kms::Result<()> {
            self.0.encrypt(aad, data).await
        }

        async fn decrypt<'a>(&self, aad: &[u8], data: &'a mut [u8]) -> kms::Result<&'a [u8]> {
            self.0.decrypt(aad, data).await
        }
    }

    pub(super) fn from_provider<K>(provider: K) -> Arc<dyn Cipher>
    where
        K: Provider + Send + Sync + 'static,
    {
        Arc::new(KmsBridge(provider))
    }
}
