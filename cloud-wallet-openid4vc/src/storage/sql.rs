use std::borrow::Cow;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use cloud_wallet_kms::provider::Provider as KmsProvider;
use sqlx::{AnyPool, ConnectOptions, FromRow, Transaction};
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

use crate::credential::{Credential, CredentialFormat, CredentialStatus};
use crate::storage::cipher::{self, Cipher};
use crate::storage::{CredentialFilter, CredentialRepository, Error, Result};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("src/storage/migrations/postgres");
static MYSQL_SQLITE_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("src/storage/migrations/mysql_sqlite");

/// Persistent relational database backend for credentials.
///
/// Supports PostgreSQL, MySQL, and SQLite databases.
#[derive(Clone)]
pub struct SqlRepository {
    pool: AnyPool,
    driver: Driver,
    cipher: Option<Arc<dyn Cipher>>,
}

impl std::fmt::Debug for SqlRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlRepository")
            .field("driver", &self.driver)
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl SqlRepository {
    /// Creates a new SQL repository using the provided connection pool.
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
    /// let storage = SqlRepository::new(pool);
    ///
    /// // Example for MySQL
    /// let pool = sqlx::any::AnyPoolOptions::new()
    ///     .connect("mysql://user:pass@localhost/db").await?;
    /// let storage = SqlRepository::new(pool);
    /// ```
    pub fn new(pool: AnyPool) -> Self {
        let driver = Driver::from_pool(&pool);
        Self {
            pool,
            driver,
            cipher: None,
        }
    }

    /// Configures the repository with a KMS provider for encrypting credential payloads.
    ///
    /// When enabled, the raw credential data is encrypted at rest using envelope encryption.
    /// After creating the backend, you should call [`init_schema`](Self::init_schema)
    /// to create the necessary tables.
    pub fn with_cipher<K>(pool: AnyPool, provider: K) -> Self
    where
        K: KmsProvider + Send + Sync + 'static,
    {
        let driver = Driver::from_pool(&pool);
        Self {
            pool,
            driver,
            cipher: Some(cipher::from_provider(provider)),
        }
    }

    /// Runs embedded database migrations to ensure required tables exist.
    #[inline]
    pub async fn init_schema(&self) -> Result<()> {
        match self.driver {
            Driver::Postgres => POSTGRES_MIGRATOR.run(&self.pool).await?,
            _ => MYSQL_SQLITE_MIGRATOR.run(&self.pool).await?,
        }
        Ok(())
    }

    /// Encrypt `raw_credential` in-place if a cipher is configured.
    /// Returns `true` if encryption occurred.
    async fn maybe_encrypt(&self, id: &Uuid, raw_credential: &mut Vec<u8>) -> Result<bool> {
        if let Some(cipher) = &self.cipher {
            cipher.encrypt(id.as_bytes(), raw_credential).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Decrypt `raw_credential` in-place if it was previously encrypted.
    async fn maybe_decrypt(
        &self,
        id: &Uuid,
        raw_credential: &mut Vec<u8>,
        payload_encrypted: bool,
    ) -> Result<()> {
        if !payload_encrypted {
            return Ok(());
        }
        let Some(cipher) = &self.cipher else {
            return Err(Error::Other(
                "credential payload is encrypted but no cipher is configured".into(),
            ));
        };

        let buf_start = raw_credential.as_ptr() as usize;
        let buf_end = buf_start + raw_credential.len();
        // Decrypt; the provider returns a sub-slice of `raw_credential`.
        let plaintext = cipher
            .decrypt(id.as_bytes(), raw_credential.as_mut_slice())
            .await?;
        let plaintext_len = plaintext.len();
        // Safety: check whether plaintext is a sub-slice of raw_credential.
        let pt_start = plaintext.as_ptr() as usize;
        let pt_end = pt_start + plaintext_len;

        if pt_start >= buf_start && pt_end <= buf_end {
            // In-buffer sub-slice: shift to front if needed, then truncate.
            let offset = pt_start - buf_start;
            if offset > 0 {
                raw_credential.copy_within(offset..offset + plaintext_len, 0);
            }
            // Compact plaintext in-place
            raw_credential.truncate(plaintext_len);
        } else {
            return Err(Error::InvalidData(
                "decrypted plaintext is not backed by source buffer".into(),
            ));
        }
        Ok(())
    }

    async fn upsert_inner(
        &self,
        tx: &mut Transaction<'_, sqlx::Any>,
        record: &CredentialRecord,
    ) -> Result<()> {
        let rows = update_credential(&self.driver, tx, record).await?;
        if rows == 0 {
            insert_credential(&self.driver, tx, record).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, FromRow)]
struct CredentialRecord {
    pub id: String,
    pub tenant_id: String,

    pub issuer: String,
    pub subject: Option<String>,

    pub credential_types: String,
    pub format: String,
    pub external_id: Option<String>,

    pub status: String,
    pub issued_at: i64,
    pub valid_until: Option<i64>,

    pub is_revoked: i64,
    pub status_location: Option<String>,
    pub status_index: Option<i64>,

    pub raw_credential: Vec<u8>,
    pub payload_encrypted: i64,
}

impl CredentialRecord {
    fn from_credential(
        credential: Credential,
        raw_credential: Vec<u8>,
        payload_encrypted: bool,
    ) -> Result<Self> {
        Ok(Self {
            id: credential.id.to_string(),
            tenant_id: credential.tenant_id.to_string(),
            issuer: credential.issuer,
            subject: credential.subject,
            credential_types: serde_json::to_string(&credential.credential_types)?,
            format: credential.format.as_str().to_owned(),
            external_id: credential.external_id,
            status: credential.status.as_str().to_owned(),
            issued_at: credential.issued_at.unix_timestamp(),
            valid_until: credential.valid_until.map(|t| t.unix_timestamp()),
            is_revoked: if credential.is_revoked { 1 } else { 0 },
            status_location: credential.status_location.map(|u| u.to_string()),
            status_index: credential.status_index,
            raw_credential,
            payload_encrypted: if payload_encrypted { 1 } else { 0 },
        })
    }

    fn parse_ids(&self) -> Result<(Uuid, Uuid)> {
        let id = Uuid::try_parse(&self.id)?;
        let tenant_id = Uuid::try_parse(&self.tenant_id)?;
        Ok((id, tenant_id))
    }

    fn into_credential_with_ids(self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let format = CredentialFormat::from_str(&self.format)?;
        let status = CredentialStatus::from_str(&self.status)?;
        let issued_at = UtcDateTime::from_unix_timestamp(self.issued_at)?;
        let valid_until = self
            .valid_until
            .map(UtcDateTime::from_unix_timestamp)
            .transpose()?;
        let status_location = self
            .status_location
            .map(|value| Url::parse(&value))
            .transpose()?;
        let credential_types = serde_json::from_str(&self.credential_types)?;
        let raw_credential = raw_credential_from_bytes(self.raw_credential)?;

        Ok(Credential {
            id,
            tenant_id,
            issuer: self.issuer,
            subject: self.subject,
            credential_types,
            format,
            external_id: self.external_id,
            status,
            issued_at,
            valid_until,
            is_revoked: self.is_revoked != 0,
            status_location,
            status_index: self.status_index,
            raw_credential,
        })
    }
}

#[async_trait::async_trait]
impl CredentialRepository for SqlRepository {
    async fn upsert(&self, mut credential: Credential) -> Result<Uuid> {
        let credential_id = credential.id;
        let mut raw_credential = std::mem::take(&mut credential.raw_credential).into_bytes();
        let payload_encrypted = self
            .maybe_encrypt(&credential.id, &mut raw_credential)
            .await?;
        let record =
            CredentialRecord::from_credential(credential, raw_credential, payload_encrypted)?;

        // Begin and commit transaction
        let mut tx = self.pool.begin().await?;
        self.upsert_inner(&mut tx, &record).await?;
        tx.commit().await?;
        Ok(credential_id)
    }

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let sql = FIND_CREDENTIAL.for_driver(&self.driver);
        let mut row = sqlx::query_as::<_, CredentialRecord>(sql)
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotFound { id, tenant_id })?;

        let (parsed_id, parsed_tenant_id) = row.parse_ids()?;
        self.maybe_decrypt(&parsed_id, &mut row.raw_credential, row.payload_encrypted != 0)
            .await?;
        row.into_credential_with_ids(parsed_id, parsed_tenant_id)
    }

    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>> {
        let encoded_types = filter
            .credential_types
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        // Build SQL and collect bind values together.
        let mut builder = FilterBuilder::new(&self.driver);

        if let Some(ref tenant_id) = filter.tenant_id {
            builder.and("tenant_id", tenant_id.to_string());
        }
        if let Some(ref types) = encoded_types {
            builder.and("credential_types", types.clone());
        }
        if let Some(ref status) = filter.status {
            builder.and("status", status.as_str().to_owned());
        }
        if let Some(ref format) = filter.format {
            builder.and("format", format.as_str().to_owned());
        }
        if let Some(ref issuer) = filter.issuer {
            builder.and("issuer", issuer.clone());
        }
        if let Some(ref subject) = filter.subject {
            builder.and("subject", subject.clone());
        }
        if filter.exclude_expired {
            builder.and_exclude_expired();
        }

        let (sql, values, expire_ts) = builder.build();
        let mut query = sqlx::query_as::<_, CredentialRecord>(&sql);

        for value in values {
            query = query.bind(value);
        }
        if let Some(ts) = expire_ts {
            query = query.bind(ts);
        }

        let rows = query.fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for mut row in rows {
            let (id, tenant_id) = row.parse_ids()?;
            self.maybe_decrypt(&id, &mut row.raw_credential, row.payload_encrypted != 0)
                .await?;
            out.push(row.into_credential_with_ids(id, tenant_id)?);
        }
        Ok(out)
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<()> {
        let result = sqlx::query(DELETE_CREDENTIAL.for_driver(&self.driver))
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(Error::NotFound { id, tenant_id });
        }
        Ok(())
    }
}

struct FilterBuilder<'d> {
    driver: &'d Driver,
    sql: String,
    values: Vec<String>,
    exclude_expired_ts: Option<i64>,
}

impl<'d> FilterBuilder<'d> {
    fn new(driver: &'d Driver) -> Self {
        let mut sql = String::with_capacity(256);
        sql.push_str("SELECT ");
        sql.push_str(SELECT_COLUMNS);
        sql.push_str(" FROM credentials WHERE 1 = 1");
        Self {
            driver,
            sql,
            values: Vec::new(),
            exclude_expired_ts: None,
        }
    }

    fn and(&mut self, column: &str, value: String) {
        let index = self.values.len() + 1;
        self.sql.push_str(" AND ");
        self.sql.push_str(column);
        self.sql.push_str(" = ");
        self.driver.write_placeholder(&mut self.sql, index);
        self.values.push(value);
    }

    fn and_exclude_expired(&mut self) {
        self.exclude_expired_ts = Some(UtcDateTime::now().unix_timestamp());
    }

    /// Consumes self, finalises the SQL, returns (sql, string_values, optional_ts).
    fn build(mut self) -> (String, Vec<String>, Option<i64>) {
        if self.exclude_expired_ts.is_some() {
            let index = self.values.len() + 1;
            self.sql
                .push_str(" AND (valid_until IS NULL OR valid_until > ");
            self.driver.write_placeholder(&mut self.sql, index);
            self.sql.push(')');
        }
        self.sql.push_str(" ORDER BY issued_at DESC");
        (self.sql, self.values, self.exclude_expired_ts)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Driver {
    Postgres,
    MySql,
    Sqlite,
}

impl Driver {
    fn from_pool(pool: &AnyPool) -> Self {
        let url = pool.connect_options().to_url_lossy();
        let url = url.as_str();
        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Self::Postgres
        } else if url.starts_with("mysql://") || url.starts_with("mariadb://") {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }

    #[inline]
    fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres)
    }

    /// Write a bind placeholder into `buf`.
    /// Postgres uses `$N`; MySQL and SQLite use `?`.
    #[inline]
    fn write_placeholder(&self, buf: &mut String, index: usize) {
        if self.is_postgres() {
            buf.push('$');
            write!(buf, "{index}").unwrap();
        } else {
            buf.push('?');
        }
    }
}

async fn insert_credential(
    driver: &Driver,
    tx: &mut Transaction<'_, sqlx::Any>,
    record: &CredentialRecord,
) -> Result<()> {
    sqlx::query(INSERT_CREDENTIAL.for_driver(driver))
        .bind(&record.id)
        .bind(&record.tenant_id)
        .bind(&record.issuer)
        .bind(record.subject.as_deref())
        .bind(&record.credential_types)
        .bind(&record.format)
        .bind(record.external_id.as_deref())
        .bind(&record.status)
        .bind(record.issued_at)
        .bind(record.valid_until)
        .bind(record.is_revoked)
        .bind(record.status_location.as_deref())
        .bind(record.status_index)
        .bind(&record.raw_credential)
        .bind(record.payload_encrypted)
        .execute(tx.as_mut())
        .await?;
    Ok(())
}

async fn update_credential(
    driver: &Driver,
    tx: &mut Transaction<'_, sqlx::Any>,
    record: &CredentialRecord,
) -> Result<u64> {
    let result = sqlx::query(UPDATE_CREDENTIAL.for_driver(driver))
        .bind(record.issuer.as_str())
        .bind(record.subject.as_deref())
        .bind(&record.credential_types)
        .bind(record.format.as_str())
        .bind(record.external_id.as_deref())
        .bind(record.status.as_str())
        .bind(record.issued_at)
        .bind(record.valid_until)
        .bind(record.is_revoked)
        .bind(record.status_location.as_deref())
        .bind(record.status_index)
        .bind(&record.raw_credential)
        .bind(record.payload_encrypted)
        .bind(record.id.as_str())
        .bind(record.tenant_id.as_str())
        .execute(tx.as_mut())
        .await?;

    Ok(result.rows_affected())
}

const SELECT_COLUMNS: &str = "id, tenant_id, issuer, subject, credential_types, format, external_id, \
     status, issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
     payload_encrypted";

static FIND_CREDENTIAL: Query = Query::new(
    "SELECT id, tenant_id, issuer, subject, credential_types, format, external_id, status, \
     issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
     payload_encrypted \
     FROM credentials WHERE id = $1 AND tenant_id = $2",
);

static INSERT_CREDENTIAL: Query = Query::new(
    "INSERT INTO credentials \
     (id, tenant_id, issuer, subject, credential_types, format, external_id, status, \
      issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
      payload_encrypted) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
);

static UPDATE_CREDENTIAL: Query = Query::new(
    "UPDATE credentials SET \
     issuer = $1, subject = $2, credential_types = $3, format = $4, external_id = $5, \
     status = $6, issued_at = $7, valid_until = $8, is_revoked = $9, status_location = $10, \
     status_index = $11, raw_credential = $12, payload_encrypted = $13 \
     WHERE id = $14 AND tenant_id = $15",
);

static DELETE_CREDENTIAL: Query =
    Query::new("DELETE FROM credentials WHERE id = $1 AND tenant_id = $2");

struct Query {
    raw: &'static str,
    rewritten: OnceLock<String>,
}

impl Query {
    const fn new(raw: &'static str) -> Self {
        Self {
            raw,
            rewritten: OnceLock::new(),
        }
    }

    fn for_driver(&self, driver: &Driver) -> &str {
        match driver {
            Driver::Postgres => self.raw,
            Driver::MySql | Driver::Sqlite => self
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
            let start_digits = index + 1;
            let mut end_digits = start_digits;
            while end_digits < bytes.len() && bytes[end_digits].is_ascii_digit() {
                end_digits += 1;
            }

            if end_digits > start_digits {
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

fn raw_credential_from_bytes(value: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(value)?)
}

impl From<sqlx::Error> for crate::storage::Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Backend(error.into())
    }
}

impl From<sqlx::migrate::MigrateError> for crate::storage::Error {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Backend(error.into())
    }
}

impl From<serde_json::Error> for crate::storage::Error {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<uuid::Error> for crate::storage::Error {
    fn from(error: uuid::Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<time::error::ComponentRange> for crate::storage::Error {
    fn from(error: time::error::ComponentRange) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<url::ParseError> for crate::storage::Error {
    fn from(error: url::ParseError) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for crate::storage::Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<&'static str> for crate::storage::Error {
    fn from(error: &'static str) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<cloud_wallet_kms::Error> for crate::storage::Error {
    fn from(error: cloud_wallet_kms::Error) -> Self {
        Self::Encryption(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_postgres_bindings_to_question_marks() {
        let sql = "SELECT * FROM credentials WHERE id = $1 AND tenant_id = $2";
        assert_eq!(
            rewrite_to_positional(sql).as_ref(),
            "SELECT * FROM credentials WHERE id = ? AND tenant_id = ?"
        );
    }

    #[test]
    fn filter_builder_no_filters_produces_valid_sql() {
        let driver = Driver::Postgres;
        let builder = FilterBuilder::new(&driver);
        let (sql, values, exclude_expired_ts) = builder.build();
        assert!(sql.contains("WHERE 1 = 1"));
        assert!(sql.ends_with("ORDER BY issued_at DESC"));
        assert!(values.is_empty());
        assert!(exclude_expired_ts.is_none());
    }

    #[test]
    fn filter_builder_postgres_uses_dollar_placeholders() {
        let driver = Driver::Postgres;
        let mut builder = FilterBuilder::new(&driver);
        builder.and("tenant_id", "abc".into());
        builder.and("status", "active".into());
        builder.and_exclude_expired();
        let (sql, values, exclude_expired_ts) = builder.build();
        assert!(sql.contains("tenant_id = $1"), "sql: {sql}");
        assert!(sql.contains("status = $2"), "sql: {sql}");
        assert!(sql.contains("valid_until > $3"), "sql: {sql}");
        assert_eq!(values.len(), 2);
        assert!(exclude_expired_ts.is_some());
    }

    #[test]
    fn filter_builder_mysql_uses_question_marks() {
        let driver = Driver::MySql;
        let mut builder = FilterBuilder::new(&driver);
        builder.and("tenant_id", "abc".into());
        builder.and_exclude_expired();
        let (sql, values, exclude_expired_ts) = builder.build();
        // MySQL/SQLite use ? for all placeholders
        assert!(!sql.contains('$'), "sql: {sql}");
        let q_count = sql.chars().filter(|&c| c == '?').count();
        assert_eq!(q_count, 2, "expected 2 placeholders, sql: {sql}");
        assert_eq!(values.len(), 1);
        assert!(exclude_expired_ts.is_some());
    }
}
