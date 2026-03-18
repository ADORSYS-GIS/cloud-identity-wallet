use crate::Result;
use crate::key::{
    dek::{DataEncryptionKey, Id},
    master::Id as MasterId,
};
use crate::storage::Storage;

use sqlx::{AnyPool, Executor, Transaction};
use time::UtcDateTime;

/// Error that can occur when working with the database storage.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error when decoding base64 data.
    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64ct::Error),
    /// The algorithm is unknown.
    #[error("Unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    /// The UNIX timestamp is invalid.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
}

impl From<Error> for crate::Error {
    fn from(err: Error) -> Self {
        crate::Error::Storage(err.into())
    }
}

/// A `Storage` backend that uses a SQL database for persistence.
///
/// This backend is compatible with any database supported by `sqlx`,
/// including PostgreSQL, MySQL, and SQLite.
#[derive(Debug, Clone)]
pub struct SqlxBackend {
    pool: AnyPool,
}

impl SqlxBackend {
    /// Creates a new `SqlxBackend` with the given connection pool.
    ///
    /// After creating the backend, you should call [`init_schema`](Self::init_schema)
    /// to create the necessary tables.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Important: Install default drivers for the database
    /// sqlx::any::install_default_drivers();
    ///
    /// // Example for PostgreSQL
    /// let pool = sqlx::any::AnyPoolOptions::new()
    ///     .connect("postgresql://user:pass@localhost/db").await?;
    /// let storage = SqlxBackend::new(pool);
    ///
    /// // Example for SQLite
    /// let pool = sqlx::any::AnyPoolOptions::new()
    ///     .connect("sqlite://data.db").await?;
    /// let storage = SqlxBackend::new(pool);
    /// ```
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Initializes the database schema.
    ///
    /// Runs the necessary SQL migrations to create the `data_encryption_keys` table
    /// required for storing DEKs. It should be called once during application setup.
    #[inline]
    pub async fn init_schema(&self) -> Result<()> {
        // Run database migrations
        sqlx::migrate!("src/storage/migrations")
            .run(&self.pool)
            .await?;
        Ok(())
    }

    async fn upsert_dek(
        &self,
        tx: &mut Transaction<'_, sqlx::Any>,
        dek: &DataEncryptionKey,
    ) -> Result<()> {
        let record = DekRecord::from(dek);
        let rows = update_dek(tx, &record).await?;
        if rows == 0 {
            insert_dek(tx, &record).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Storage for SqlxBackend {
    async fn upsert_dek(&self, dek: &DataEncryptionKey) -> Result<()> {
        // Start a transaction
        let mut tx = self.pool.begin().await?;
        self.upsert_dek(&mut tx, dek).await?;
        // Commit the transaction
        tx.commit().await?;
        Ok(())
    }

    async fn get_dek(&self, id: &Id) -> Result<Option<DataEncryptionKey>> {
        let row = sqlx::query_as::<_, DekRecord>(
            "SELECT id, master_id, encrypted_key,
                algorithm, created_at, last_accessed
            FROM data_encryption_keys WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(db) => {
                // Update last accessed time
                let mut dek = DataEncryptionKey::try_from(db)?;
                let now = UtcDateTime::now();
                tokio::spawn(update_last_accessed(
                    self.pool.clone(),
                    id.as_str().into(),
                    now,
                ));
                dek.last_accessed = Some(now);
                Ok(Some(dek))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct DekRecord {
    pub id: String,
    pub master_id: String,
    pub encrypted_key: String,
    pub algorithm: String,
    pub created_at: i64,
    pub last_accessed: Option<i64>,
}

impl From<&DataEncryptionKey> for DekRecord {
    fn from(dek: &DataEncryptionKey) -> Self {
        use base64ct::{Base64Unpadded, Encoding};

        Self {
            id: dek.id.to_string(),
            master_id: dek.master_key_id.to_string(),
            encrypted_key: Base64Unpadded::encode_string(&dek.encrypted_key),
            algorithm: dek.algorithm.to_string(),
            created_at: dek.created_at.unix_timestamp(),
            last_accessed: dek.last_accessed.map(|t| t.unix_timestamp()),
        }
    }
}

impl TryFrom<DekRecord> for DataEncryptionKey {
    type Error = Error;

    fn try_from(row: DekRecord) -> std::result::Result<Self, Self::Error> {
        use base64ct::{Base64Unpadded as B64, Encoding};
        use std::str::FromStr;
        use time::UtcDateTime;

        let algorithm = crate::AeadAlgorithm::from_str(&row.algorithm)
            .map_err(|e| Error::UnknownAlgorithm(e.to_string()))?;
        let created_at = UtcDateTime::from_unix_timestamp(row.created_at)?;
        let last_accessed = row
            .last_accessed
            .map(UtcDateTime::from_unix_timestamp)
            .transpose()?;

        Ok(Self {
            id: Id::from(row.id),
            master_key_id: MasterId::from(row.master_id),
            encrypted_key: B64::decode_vec(&row.encrypted_key)?.into(),
            plaintext_key: None,
            algorithm,
            created_at,
            last_accessed,
        })
    }
}

async fn insert_dek(tx: &mut Transaction<'_, sqlx::Any>, record: &DekRecord) -> Result<()> {
    let query = sqlx::query(
        r#"
        INSERT INTO data_encryption_keys 
        (id, master_id, encrypted_key, algorithm, created_at, last_accessed)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(record.id.as_str())
    .bind(record.master_id.as_str())
    .bind(&record.encrypted_key)
    .bind(&record.algorithm)
    .bind(record.created_at)
    .bind(record.last_accessed);
    tx.execute(query).await?;
    Ok(())
}

async fn update_dek(tx: &mut Transaction<'_, sqlx::Any>, record: &DekRecord) -> Result<u64> {
    let query = sqlx::query(
        r#"
        UPDATE data_encryption_keys 
        SET master_id = ?, encrypted_key = ?, algorithm = ?,
            created_at = ?, last_accessed = ?
        WHERE id = ?
        "#,
    )
    .bind(record.master_id.as_str())
    .bind(&record.encrypted_key)
    .bind(&record.algorithm)
    .bind(record.created_at)
    .bind(record.last_accessed)
    .bind(record.id.as_str());
    Ok(tx.execute(query).await?.rows_affected())
}

async fn update_last_accessed(pool: AnyPool, id: String, now: UtcDateTime) -> Result<()> {
    sqlx::query("UPDATE data_encryption_keys SET last_accessed = ? WHERE id = ?")
        .bind(now.unix_timestamp())
        .bind(&id)
        .execute(&pool)
        .await?;
    Ok(())
}

impl From<sqlx::Error> for crate::Error {
    fn from(error: sqlx::Error) -> Self {
        crate::Error::Storage(error.into())
    }
}

impl From<sqlx::migrate::MigrateError> for crate::Error {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        crate::Error::Storage(error.into())
    }
}

impl From<time::error::ComponentRange> for Error {
    fn from(error: time::error::ComponentRange) -> Self {
        Error::InvalidTimestamp(error.to_string())
    }
}
