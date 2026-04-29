//! Tenant repository implementations.
//!
//! Provides both SQL-based and in-memory storage backends for tenant data.

use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use cloud_wallet_crypto::{
    ecdsa::{Curve, KeyPair as EcdsaKeyPair},
    ed25519::KeyPair as Ed25519KeyPair,
    rsa::{KeyPair as RsaKeyPair, RsaKeySize},
};
use cloud_wallet_kms::provider::Provider as KmsProvider;
use dashmap::DashMap;
use sqlx::{AnyPool, FromRow};
use time::UtcDateTime;
use uuid::Uuid;

use crate::domain::models::tenants::{
    RegisterTenantRequest, SignAlgorithm, TenantError, TenantKey, TenantName, TenantResponse,
};
use crate::domain::ports::TenantRepo;
use crate::outbound::cipher::{self, Cipher};
use crate::utils::{Driver, Query};

type Result<T> = std::result::Result<T, TenantError>;

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");
static MYSQL_SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/mysql_sqlite");

/// Algorithm used for tenant key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TenantKeyAlg {
    Ecdsa(Curve),
    EdDsa,
    Rsa(RsaKeySize),
}

/// SQL-based tenant repository implementation.
///
/// Supports PostgreSQL, MySQL, and SQLite databases.
#[derive(Clone)]
pub struct SqlTenantRepo {
    pool: AnyPool,
    driver: Driver,
    alg: TenantKeyAlg,
    cipher: Arc<dyn Cipher>,
}

impl std::fmt::Debug for SqlTenantRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlTenantRepo")
            .field("driver", &self.driver)
            .field("alg", &self.alg)
            .field("cipher_enabled", &true)
            .finish()
    }
}

impl SqlTenantRepo {
    /// Creates a new SQL tenant repository with the given connection pool.
    pub fn new<K>(pool: AnyPool, alg: TenantKeyAlg, kms_provider: K) -> Self
    where
        K: KmsProvider + Send + Sync + 'static,
    {
        let driver = Driver::from_pool(&pool);
        Self {
            pool,
            driver,
            alg,
            cipher: cipher::from_provider(kms_provider),
        }
    }

    /// Runs embedded database migrations to ensure required tables exist.
    pub async fn init_schema(&self) -> Result<()> {
        match self.driver {
            Driver::Postgres => POSTGRES_MIGRATOR.run(&self.pool).await?,
            _ => MYSQL_SQLITE_MIGRATOR.run(&self.pool).await?,
        }
        Ok(())
    }
}

#[async_trait]
impl TenantRepo for SqlTenantRepo {
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse> {
        let tenant_name = TenantName::new(request.name).map_err(TenantError::InvalidName)?;
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let name = tenant_name.into_inner();
        let created_at = UtcDateTime::now();
        let (algorithm, mut key) = generate_key(self.alg)?;
        self.cipher.encrypt(id.as_bytes(), &mut key).await?;

        sqlx::query(INSERT_TENANT.for_driver(&self.driver))
            .bind(&id_str)
            .bind(name.as_str())
            .bind(algorithm.as_str())
            .bind(&*key)
            .bind(created_at.unix_timestamp())
            .execute(&self.pool)
            .await?;

        Ok(TenantResponse {
            tenant_id: id_str,
            name,
        })
    }

    async fn find_key(&self, id: Uuid) -> Result<TenantKey> {
        let mut row =
            sqlx::query_as::<_, TenantKeyRecord>(FIND_TENANT_KEY.for_driver(&self.driver))
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(TenantError::NotFound { id })?;

        let algorithm = SignAlgorithm::from_str(&row.key_algorithm)?;
        decrypt_key_material(&*self.cipher, id, &mut row.key_material).await?;

        Ok(TenantKey {
            algorithm,
            der_bytes: row.key_material.into(),
        })
    }
}

/// In-memory tenant repository implementation.
///
/// Since this is an in-memory implementation, it is not persistent and
/// will not survive restarts. It is mainly used for testing and development.
#[derive(Clone)]
pub struct MemoryTenantRepo {
    tenants: Arc<DashMap<Uuid, StoredTenantKey>>,
    alg: TenantKeyAlg,
    cipher: Option<Arc<dyn Cipher>>,
}

#[derive(Debug, Clone)]
struct StoredTenantKey {
    algorithm: SignAlgorithm,
    key_material: Vec<u8>,
    encrypted: bool,
}

impl std::fmt::Debug for MemoryTenantRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryTenantRepo")
            .field("tenants_len", &self.tenants.len())
            .field("alg", &self.alg)
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl Default for MemoryTenantRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTenantRepo {
    /// Creates a new, empty in-memory tenant repository.
    pub fn new() -> Self {
        Self {
            tenants: Arc::default(),
            alg: TenantKeyAlg::Ecdsa(Curve::P256),
            cipher: None,
        }
    }

    /// Creates a new in-memory repository with key encryption enabled.
    pub fn with_cipher<K>(alg: TenantKeyAlg, kms_provider: K) -> Self
    where
        K: KmsProvider + Send + Sync + 'static,
    {
        Self {
            tenants: Arc::default(),
            alg,
            cipher: Some(cipher::from_provider(kms_provider)),
        }
    }

    async fn maybe_encrypt_key(&self, id: Uuid, key: &mut Vec<u8>) -> Result<bool> {
        if let Some(cipher) = &self.cipher {
            cipher.encrypt(id.as_bytes(), key).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[async_trait]
impl TenantRepo for MemoryTenantRepo {
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse> {
        let tenant_name = TenantName::new(request.name).map_err(TenantError::InvalidName)?;
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let name = tenant_name.into_inner();
        let (algorithm, mut key_material) = generate_key(self.alg)?;
        let encrypted = self.maybe_encrypt_key(id, &mut key_material).await?;

        self.tenants.insert(
            id,
            StoredTenantKey {
                algorithm,
                key_material,
                encrypted,
            },
        );

        Ok(TenantResponse {
            tenant_id: id_str,
            name,
        })
    }

    async fn find_key(&self, id: Uuid) -> Result<TenantKey> {
        let entry = self.tenants.get(&id).ok_or(TenantError::NotFound { id })?;
        let mut key = entry.key_material.clone();
        let algorithm = entry.algorithm;
        let encrypted = entry.encrypted;
        drop(entry);

        if encrypted {
            let cipher = self.cipher.as_ref().ok_or_else(|| {
                TenantError::InvalidData(
                    "tenant key material is encrypted but no cipher is configured".to_string(),
                )
            })?;
            decrypt_key_material(cipher.as_ref(), id, &mut key).await?;
        }

        Ok(TenantKey {
            algorithm,
            der_bytes: key.into(),
        })
    }
}

static INSERT_TENANT: Query = Query::new(
    "INSERT INTO tenants (id, name, key_algorithm, key_material, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
);

static FIND_TENANT_KEY: Query =
    Query::new("SELECT key_algorithm, key_material FROM tenants WHERE id = $1");

#[derive(Debug, FromRow)]
struct TenantKeyRecord {
    key_algorithm: String,
    key_material: Vec<u8>,
}

fn generate_key(alg: TenantKeyAlg) -> Result<(SignAlgorithm, Vec<u8>)> {
    match alg {
        TenantKeyAlg::Ecdsa(curve) => {
            let key = EcdsaKeyPair::generate(curve)?;
            Ok((SignAlgorithm::Ecdsa, key.to_pkcs8_der().to_vec()))
        }
        TenantKeyAlg::EdDsa => {
            let key = Ed25519KeyPair::generate()?;
            let mut buf = vec![0u8; 100];
            let der_len = key.to_pkcs8_der(&mut buf)?.len();
            compact_in_place(&mut buf, der_len)?;
            Ok((SignAlgorithm::EdDsa, buf))
        }
        TenantKeyAlg::Rsa(size) => {
            let key = RsaKeyPair::generate(size)?;
            let mut buf = vec![0u8; key.modulus_len() * 5];
            let der_len = key.to_pkcs8_der(&mut buf)?.len();
            compact_in_place(&mut buf, der_len)?;
            Ok((SignAlgorithm::Rsa, buf))
        }
    }
}

fn compact_in_place(buffer: &mut Vec<u8>, data_len: usize) -> Result<()> {
    if data_len > buffer.len() {
        return Err(TenantError::InvalidData(
            "data is outside source buffer".to_string(),
        ));
    }
    buffer.truncate(data_len);
    Ok(())
}

async fn decrypt_key_material(
    cipher: &dyn Cipher,
    id: Uuid,
    key_material: &mut Vec<u8>,
) -> Result<()> {
    let plaintext = cipher
        .decrypt(id.as_bytes(), key_material.as_mut_slice())
        .await?;
    let plaintext_len = plaintext.len();

    if plaintext_len > key_material.len() {
        return Err(TenantError::InvalidData(
            "decrypted tenant key is not backed by source buffer".into(),
        ));
    }
    key_material.truncate(plaintext_len);
    Ok(())
}

impl From<sqlx::Error> for TenantError {
    fn from(error: sqlx::Error) -> Self {
        Self::Backend(error.into())
    }
}

impl From<sqlx::migrate::MigrateError> for TenantError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Backend(error.into())
    }
}

impl From<cloud_wallet_kms::Error> for TenantError {
    fn from(error: cloud_wallet_kms::Error) -> Self {
        Self::Encryption(Box::new(error))
    }
}

impl From<cloud_wallet_crypto::Error> for TenantError {
    fn from(error: cloud_wallet_crypto::Error) -> Self {
        Self::Encryption(Box::new(error))
    }
}

impl From<&'static str> for TenantError {
    fn from(error: &'static str) -> Self {
        Self::InvalidData(error.to_string())
    }
}
