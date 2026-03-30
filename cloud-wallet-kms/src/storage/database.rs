use std::borrow::Cow;
use std::sync::OnceLock;

use crate::Result;
use crate::key::{
    dek::{DataEncryptionKey, Id},
    master::Id as MasterId,
};
use crate::storage::Storage;

use sqlx::{AnyPool, ConnectOptions, Transaction};
use time::UtcDateTime;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("src/storage/migrations");

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
    driver: Driver,
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
        let driver = Driver::from_pool(&pool);
        Self { pool, driver }
    }

    /// Initializes the database schema.
    ///
    /// Runs the necessary SQL migrations to create the `data_encryption_keys` table
    /// required for storing DEKs. It should be called once during application setup.
    #[inline]
    pub async fn init_schema(&self) -> Result<()> {
        // Run database migrations
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    async fn upsert_dek(
        &self,
        tx: &mut Transaction<'_, sqlx::Any>,
        dek: &DataEncryptionKey,
    ) -> Result<()> {
        let record = DekRecord::from(dek);
        let rows = update_dek(&self.driver, tx, &record).await?;
        if rows == 0 {
            insert_dek(&self.driver, tx, &record).await?;
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
        let sql = FIND_DEK.for_driver(&self.driver);
        let row = sqlx::query_as::<_, DekRecord>(sql)
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(db) => {
                // Update last accessed time
                let mut dek = DataEncryptionKey::try_from(db)?;
                let now = UtcDateTime::now();
                let driver = self.driver.clone();
                tokio::spawn(update_last_accessed(
                    driver,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Driver {
    Postgres,
    MySql,
    Sqlite,
}

impl Driver {
    fn from_pool(pool: &AnyPool) -> Self {
        let db_url = pool.connect_options().to_url_lossy();
        if db_url.as_str().starts_with("postgres") {
            Driver::Postgres
        } else if db_url.as_str().starts_with("mysql") {
            Driver::MySql
        } else {
            Driver::Sqlite
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

async fn insert_dek(
    driver: &Driver,
    tx: &mut Transaction<'_, sqlx::Any>,
    record: &DekRecord,
) -> Result<()> {
    sqlx::query(INSERT_DEK.for_driver(driver))
        .bind(record.id.as_str())
        .bind(record.master_id.as_str())
        .bind(&record.encrypted_key)
        .bind(&record.algorithm)
        .bind(record.created_at)
        .bind(record.last_accessed)
        .execute(tx.as_mut())
        .await?;
    Ok(())
}

async fn update_dek(
    driver: &Driver,
    tx: &mut Transaction<'_, sqlx::Any>,
    record: &DekRecord,
) -> Result<u64> {
    let result = sqlx::query(UPDATE_DEK.for_driver(driver))
        .bind(record.master_id.as_str())
        .bind(&record.encrypted_key)
        .bind(&record.algorithm)
        .bind(record.created_at)
        .bind(record.last_accessed)
        .bind(record.id.as_str())
        .execute(tx.as_mut())
        .await?;
    Ok(result.rows_affected())
}

async fn update_last_accessed(
    driver: Driver,
    pool: AnyPool,
    id: String,
    now: UtcDateTime,
) -> Result<()> {
    sqlx::query(UPDATE_LAST_ACCESSED.for_driver(&driver))
        .bind(now.unix_timestamp())
        .bind(&id)
        .execute(&pool)
        .await?;
    Ok(())
}

static FIND_DEK: Query = Query::new(
    "SELECT id, master_id, encrypted_key, algorithm, created_at, last_accessed \
     FROM data_encryption_keys WHERE id = $1",
);

static INSERT_DEK: Query = Query::new(
    "INSERT INTO data_encryption_keys \
     (id, master_id, encrypted_key, algorithm, created_at, last_accessed) \
     VALUES ($1, $2, $3, $4, $5, $6)",
);

static UPDATE_DEK: Query = Query::new(
    "UPDATE data_encryption_keys SET \
     master_id = $1, encrypted_key = $2, algorithm = $3, created_at = $4, last_accessed = $5 \
     WHERE id = $6",
);

static UPDATE_LAST_ACCESSED: Query =
    Query::new("UPDATE data_encryption_keys SET last_accessed = $1 WHERE id = $2");

struct Query {
    raw: &'static str,
    rewritten: OnceLock<String>,
}

impl Query {
    const fn new(sql: &'static str) -> Self {
        Self {
            raw: sql,
            rewritten: OnceLock::new(),
        }
    }

    fn for_driver(&self, driver: &Driver) -> &str {
        match driver {
            Driver::Postgres => self.raw,
            _ => self
                .rewritten
                .get_or_init(|| rewrite_to_positional(self.raw).into_owned()),
        }
    }
}

fn rewrite_to_positional(sql: &str) -> Cow<'_, str> {
    let bytes = sql.as_bytes();
    let mut result = String::with_capacity(sql.len());
    let mut last = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'$' {
            // Peek ahead — must be followed by at least one digit
            let start_digits = index + 1;
            let mut end_digits = start_digits;
            while end_digits < bytes.len() && bytes[end_digits].is_ascii_digit() {
                end_digits += 1;
            }
            if end_digits > start_digits {
                // Flush unchanged segment before the `$N`
                result.push_str(&sql[last..index]);
                result.push('?');
                index = end_digits;
                last = index;
                continue;
            }
        }
        index += 1;
    }
    result.push_str(&sql[last..]);
    Cow::Owned(result)
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
