use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cloud_wallet_kms::provider::Provider as KmsProvider;
use dashmap::DashMap;
use sqlx::{AnyPool, FromRow, Transaction};
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

use crate::domain::models::credential::{
    Credential, CredentialError, CredentialFilter, CredentialFormat, CredentialStatus,
};
use crate::domain::ports::CredentialRepo;
use crate::outbound::cipher::{self, Cipher};
use crate::utils::{Driver, Query};

type Result<T> = std::result::Result<T, CredentialError>;

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");
static MYSQL_SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/mysql_sqlite");

/// Persistent relational database backend for credentials.
///
/// Supports PostgreSQL, MySQL, and SQLite databases.
#[derive(Clone)]
pub struct SqlCredentialRepo {
    pool: AnyPool,
    driver: Driver,
    cipher: Option<Arc<dyn Cipher>>,
}

impl std::fmt::Debug for SqlCredentialRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlRepository")
            .field("driver", &self.driver)
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl SqlCredentialRepo {
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
            return Err(CredentialError::Other(
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
            return Err(CredentialError::InvalidData(
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
impl CredentialRepo for SqlCredentialRepo {
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
            .ok_or(CredentialError::NotFound { id, tenant_id })?;

        let (parsed_id, parsed_tenant_id) = row.parse_ids()?;
        self.maybe_decrypt(
            &parsed_id,
            &mut row.raw_credential,
            row.payload_encrypted != 0,
        )
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
        sqlx::query(DELETE_CREDENTIAL.for_driver(&self.driver))
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .execute(&self.pool)
            .await?;
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
            values: vec![],
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

fn raw_credential_from_bytes(value: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(value)?)
}

/// A volatile, in-memory credential storage backend.
///
/// Useful for tests or local development where data persistence across restarts
/// is not required.
#[derive(Clone)]
pub struct MemoryCredentialRepo {
    credentials: Arc<DashMap<(Uuid, Uuid), StoredCredential>>,
    cipher: Option<Arc<dyn Cipher>>,
}

#[derive(Clone)]
struct StoredCredential {
    credential: Credential,
    raw_credential: Vec<u8>,
    payload_encrypted: bool,
}

impl std::fmt::Debug for MemoryCredentialRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryRepository")
            .field("credentials_len", &self.credentials.len())
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl Default for MemoryCredentialRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCredentialRepo {
    /// Creates a new, empty in-memory repository.
    pub fn new() -> Self {
        Self {
            credentials: Arc::default(),
            cipher: None,
        }
    }

    /// Configures the repository with a KMS provider for encrypting credential payloads.
    ///
    /// By default, the `MemoryCredentialRepo` does not encrypt data. Calling this method
    /// enables payload encryption and decryption using the provided KMS provider.
    pub fn with_cipher<K: KmsProvider + Send + Sync + 'static>(provider: K) -> Self {
        Self {
            credentials: Arc::default(),
            cipher: Some(cipher::from_provider(provider)),
        }
    }

    /// Encrypts the raw credential payload if a cipher is configured.
    async fn maybe_encrypt(&self, id: &Uuid, raw_credential: &mut Vec<u8>) -> Result<bool> {
        if let Some(cipher) = &self.cipher {
            cipher
                .encrypt(id.as_bytes(), raw_credential)
                .await
                .map_err(|e| CredentialError::Encryption(e.into()))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Decrypts the raw credential payload if it was previously encrypted.
    async fn maybe_decrypt(&self, entry: &StoredCredential) -> Result<Credential> {
        let mut credential = entry.credential.clone();
        let mut raw_credential = entry.raw_credential.clone();

        if entry.payload_encrypted {
            let Some(cipher) = &self.cipher else {
                return Err(CredentialError::Other(
                    "credential payload is encrypted but no cipher is configured".into(),
                ));
            };

            let dst = raw_credential.as_ptr() as usize;
            let plaintext = cipher
                .decrypt(credential.id.as_bytes(), raw_credential.as_mut_slice())
                .await
                .map_err(|e| CredentialError::Encryption(e.into()))?;
            let src = plaintext.as_ptr() as usize;
            let plaintext_len = plaintext.len();
            let offset = src.checked_sub(dst).ok_or_else(|| {
                CredentialError::InvalidData(
                    "decrypted plaintext is not backed by source buffer".into(),
                )
            })?;
            compact_plaintext_in_place(&mut raw_credential, offset, plaintext_len)?;
        }
        credential.raw_credential = raw_credential_from_bytes(raw_credential)?;
        Ok(credential)
    }
}

/// Helper function to compact the plaintext in place after decryption.
fn compact_plaintext_in_place(
    buffer: &mut Vec<u8>,
    plaintext_offset: usize,
    plaintext_len: usize,
) -> Result<()> {
    let end = plaintext_offset + plaintext_len;
    if end > buffer.len() {
        return Err(CredentialError::InvalidData(
            "decrypted plaintext is outside source buffer".to_string(),
        ));
    }

    if plaintext_offset > 0 {
        buffer.copy_within(plaintext_offset..end, 0);
    }
    buffer.truncate(plaintext_len);
    Ok(())
}

#[async_trait]
impl CredentialRepo for MemoryCredentialRepo {
    async fn upsert(&self, mut credential: Credential) -> Result<Uuid> {
        let credential_id = credential.id;
        let mut raw_credential = std::mem::take(&mut credential.raw_credential).into_bytes();
        let payload_encrypted = self
            .maybe_encrypt(&credential.id, &mut raw_credential)
            .await?;
        let key = (credential.tenant_id, credential.id);
        self.credentials.insert(
            key,
            StoredCredential {
                credential,
                raw_credential,
                payload_encrypted,
            },
        );
        Ok(credential_id)
    }

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let entry = self
            .credentials
            .get(&(tenant_id, id))
            .ok_or(CredentialError::NotFound { id, tenant_id })?;
        self.maybe_decrypt(entry.value()).await
    }

    async fn list(&self, filter: CredentialFilter) -> Result<Vec<Credential>> {
        let mut out = Vec::with_capacity(self.credentials.len());

        for entry in self.credentials.iter() {
            let stored = entry.value();

            if filter.matches(&stored.credential) {
                out.push(self.maybe_decrypt(stored).await?);
            }
        }

        out.sort_by_key(|b| std::cmp::Reverse(b.issued_at));
        Ok(out)
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<()> {
        self.credentials
            .remove(&(tenant_id, id))
            .ok_or(CredentialError::NotFound { id, tenant_id })?;
        Ok(())
    }
}

impl From<sqlx::Error> for CredentialError {
    fn from(error: sqlx::Error) -> Self {
        Self::Backend(error.into())
    }
}

impl From<sqlx::migrate::MigrateError> for CredentialError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Backend(error.into())
    }
}

impl From<serde_json::Error> for CredentialError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<uuid::Error> for CredentialError {
    fn from(error: uuid::Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<time::error::ComponentRange> for CredentialError {
    fn from(error: time::error::ComponentRange) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<url::ParseError> for CredentialError {
    fn from(error: url::ParseError) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CredentialError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<&'static str> for CredentialError {
    fn from(error: &'static str) -> Self {
        Self::InvalidData(error.to_string())
    }
}

impl From<cloud_wallet_kms::Error> for CredentialError {
    fn from(error: cloud_wallet_kms::Error) -> Self {
        Self::Encryption(Box::new(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[derive(Debug, Clone, Copy)]
    struct PrefixCipher;

    const PREFIX: &[u8] = b"encrypted:";

    #[async_trait::async_trait]
    impl KmsProvider for PrefixCipher {
        async fn encrypt<T>(
            &self,
            _key_id: &[u8],
            plaintext: &mut T,
        ) -> cloud_wallet_kms::Result<()>
        where
            T: AsMut<[u8]> + for<'a> Extend<&'a u8> + Send,
        {
            plaintext.extend(PREFIX.iter());
            let payload = plaintext.as_mut();
            let plaintext_len = payload.len() - PREFIX.len();
            payload.copy_within(0..plaintext_len, PREFIX.len());
            payload[..PREFIX.len()].copy_from_slice(PREFIX);
            Ok(())
        }

        async fn decrypt<'a>(
            &self,
            _key_id: &[u8],
            ciphertext: &'a mut [u8],
        ) -> cloud_wallet_kms::Result<&'a [u8]> {
            if ciphertext.starts_with(PREFIX) {
                Ok(&ciphertext[PREFIX.len()..])
            } else {
                Err(cloud_wallet_kms::Error::Other("invalid prefix".to_string()))
            }
        }
    }

    fn sample_credential(tenant_id: Uuid) -> Credential {
        Credential {
            id: Uuid::new_v4(),
            tenant_id,
            issuer: "https://issuer.example".to_string(),
            subject: Some("did:example:alice".to_string()),
            credential_types: vec![
                "VerifiableCredential".to_string(),
                "EmployeeBadge".to_string(),
            ],
            format: CredentialFormat::JwtVcJson,
            external_id: Some("ext-123".to_string()),
            status: CredentialStatus::Active,
            issued_at: UtcDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            valid_until: Some(UtcDateTime::from_unix_timestamp(2_000_000_000).unwrap()),
            is_revoked: false,
            status_location: Some(Url::parse("https://status.example/1").unwrap()),
            status_index: Some(7),
            raw_credential: "{\"vc\":\"payload\"}".to_string(),
        }
    }

    #[tokio::test]
    async fn in_memory_crud_roundtrip() {
        let repo = MemoryCredentialRepo::with_cipher(PrefixCipher);
        let tenant_id = Uuid::new_v4();
        let credential = sample_credential(tenant_id);

        repo.upsert(credential.clone()).await.unwrap();

        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();
        assert_eq!(found.id, credential.id);
        assert_eq!(found.raw_credential, credential.raw_credential);

        let listed = repo
            .list(CredentialFilter {
                tenant_id: Some(tenant_id),
                format: Some(CredentialFormat::JwtVcJson),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        repo.delete(credential.id, tenant_id).await.unwrap();
        assert!(repo.find_by_id(credential.id, tenant_id).await.is_err());
    }

    #[tokio::test]
    async fn in_memory_with_cipher_decrypts_on_read() {
        let repo = MemoryCredentialRepo::with_cipher(PrefixCipher);
        let tenant_id = Uuid::new_v4();
        let credential = sample_credential(tenant_id);

        repo.upsert(credential.clone()).await.unwrap();
        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();

        assert_eq!(found.raw_credential, credential.raw_credential);
    }
}
