use core::str::FromStr;
use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use cloud_wallet_kms::provider::Provider as KmsProvider;
use serde_json::Value;
use sqlx::{AnyPool, ConnectOptions, FromRow, Transaction};
use time::UtcDateTime;
use url::Url;
use uuid::Uuid;

use crate::credential::{Credential, CredentialFormat, CredentialStatus};
use crate::storage::{CredentialFilter, CredentialRepository, Error, Result};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("src/storage/migrations/postgres");
static MYSQL_SQLITE_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("src/storage/migrations/mysql_sqlite");

#[derive(Clone)]
pub struct SqlRepository<K> {
    pool: AnyPool,
    driver: Driver,
    cipher: Option<Arc<K>>,
}

impl<K> std::fmt::Debug for SqlRepository<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlRepository")
            .field("driver", &self.driver)
            .field("cipher_enabled", &self.cipher.is_some())
            .finish()
    }
}

impl<K: KmsProvider> SqlRepository<K> {
    pub fn new(pool: AnyPool) -> Self {
        let driver = Driver::from_pool(&pool);
        Self {
            pool,
            driver,
            cipher: None,
        }
    }

    pub fn with_cipher(pool: AnyPool, cipher: K) -> Self {
        let driver = Driver::from_pool(&pool);
        Self {
            pool,
            driver,
            cipher: Some(Arc::new(cipher)),
        }
    }

    #[inline]
    pub async fn init_schema(&self) -> Result<()> {
        match self.driver {
            Driver::Postgres => POSTGRES_MIGRATOR.run(&self.pool).await?,
            Driver::MySql | Driver::Sqlite => MYSQL_SQLITE_MIGRATOR.run(&self.pool).await?,
        }
        Ok(())
    }

    async fn maybe_encrypt(&self, id: &Uuid, raw_credential: &mut Vec<u8>) -> Result<bool> {
        if let Some(cipher) = &self.cipher {
            cipher.encrypt(id.as_bytes(), raw_credential).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn maybe_decrypt(
        &self,
        id: &Uuid,
        raw_credential: &mut Vec<u8>,
        payload_encrypted: bool,
    ) -> Result<()> {
        if payload_encrypted {
            let Some(cipher) = &self.cipher else {
                return Err(Error::Other(
                    "credential payload is encrypted but no cipher is configured".to_string(),
                ));
            };

            let dst = raw_credential.as_ptr() as usize;
            let plaintext = cipher
                .decrypt(id.as_bytes(), raw_credential.as_mut_slice())
                .await?;
            let src = plaintext.as_ptr() as usize;
            let plaintext_len = plaintext.len();
            let offset = src.checked_sub(dst).ok_or_else(|| {
                Error::InvalidData("decrypted plaintext is not backed by source buffer".to_string())
            })?;
            compact_plaintext_in_place(raw_credential, offset, plaintext_len)?;
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

    fn placeholder(&self, index: usize) -> String {
        if self.driver == Driver::Postgres {
            format!("${index}")
        } else {
            "?".into()
        }
    }

    fn select_columns(&self) -> &'static str {
        select_columns_for_driver(&self.driver)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct CredentialRecord {
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
            credential_types: serde_json::to_string(&credential.credential_types)
                .map_err(|e| Error::InvalidData(e.to_string()))?,
            format: credential.format.as_str().to_owned(),
            external_id: credential.external_id,
            status: credential.status.as_str().to_owned(),
            issued_at: credential.issued_at.unix_timestamp(),
            valid_until: credential.valid_until.map(|t| t.unix_timestamp()),
            is_revoked: i64::from(credential.is_revoked),
            status_location: credential.status_location.map(|u| u.to_string()),
            status_index: credential.status_index,
            raw_credential,
            payload_encrypted: i64::from(payload_encrypted),
        })
    }

    fn parse_ids(&self) -> Result<(Uuid, Uuid)> {
        let id = Uuid::parse_str(&self.id)
            .map_err(|e| Error::InvalidData(format!("invalid credential id '{}': {e}", self.id)))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id).map_err(|e| {
            Error::InvalidData(format!("invalid tenant id '{}': {e}", self.tenant_id))
        })?;
        Ok((id, tenant_id))
    }

    fn into_credential_with_ids(self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let format = CredentialFormat::from_str(&self.format).map_err(|e| {
            Error::InvalidData(format!("invalid credential format '{}': {e}", self.format))
        })?;
        let status = CredentialStatus::from_str(&self.status).map_err(|e| {
            Error::InvalidData(format!("invalid credential status '{}': {e}", self.status))
        })?;
        let issued_at = UtcDateTime::from_unix_timestamp(self.issued_at).map_err(|e| {
            Error::InvalidData(format!(
                "invalid issued_at timestamp '{}': {e}",
                self.issued_at
            ))
        })?;
        let valid_until = self
            .valid_until
            .map(UtcDateTime::from_unix_timestamp)
            .transpose()
            .map_err(|e| Error::InvalidData(format!("invalid valid_until timestamp: {e}")))?;
        let status_location = self
            .status_location
            .map(|value| {
                Url::parse(&value)
                    .map_err(|e| Error::InvalidData(format!("invalid status_location: {e}")))
            })
            .transpose()?;
        let credential_types = serde_json::from_str::<Value>(&self.credential_types)
            .map_err(|e| Error::InvalidData(e.to_string()))?;

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
            raw_credential: self.raw_credential.into_boxed_slice(),
        })
    }
}

#[async_trait::async_trait]
impl<K: KmsProvider> CredentialRepository for SqlRepository<K> {
    async fn upsert(&self, mut credential: Credential) -> Result<()> {
        let mut raw_credential = std::mem::take(&mut credential.raw_credential).into_vec();
        let payload_encrypted = self
            .maybe_encrypt(&credential.id, &mut raw_credential)
            .await?;
        let record =
            CredentialRecord::from_credential(credential, raw_credential, payload_encrypted)?;

        let mut tx = self.pool.begin().await?;
        self.upsert_inner(&mut tx, &record).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid, tenant_id: Uuid) -> Result<Credential> {
        let sql = find_credential_query(&self.driver).for_driver(&self.driver);
        let mut row = sqlx::query_as::<_, CredentialRecord>(sql)
            .bind(id.to_string())
            .bind(tenant_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotFound { id, tenant_id })?;

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
        let mut sql = format!(
            "SELECT {} FROM credentials WHERE 1 = 1",
            self.select_columns()
        );
        let mut bind_index = 1usize;

        let encoded_credential_types = filter
            .credential_types
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| Error::InvalidData(e.to_string()))?;

        if filter.tenant_id.is_some() {
            sql.push_str(" AND tenant_id = ");
            sql.push_str(&self.placeholder(bind_index));
            bind_index += 1;
        }
        if encoded_credential_types.is_some() {
            sql.push_str(" AND credential_types = ");
            let placeholder = self.placeholder(bind_index);
            append_json_bind_expr(&mut sql, &self.driver, &placeholder);
            bind_index += 1;
        }
        if filter.status.is_some() {
            sql.push_str(" AND status = ");
            sql.push_str(&self.placeholder(bind_index));
            bind_index += 1;
        }
        if filter.format.is_some() {
            sql.push_str(" AND format = ");
            sql.push_str(&self.placeholder(bind_index));
            bind_index += 1;
        }
        if filter.issuer.is_some() {
            sql.push_str(" AND issuer = ");
            sql.push_str(&self.placeholder(bind_index));
            bind_index += 1;
        }
        if filter.subject.is_some() {
            sql.push_str(" AND subject = ");
            sql.push_str(&self.placeholder(bind_index));
            bind_index += 1;
        }
        if filter.exclude_expired {
            sql.push_str(" AND (valid_until IS NULL OR valid_until > ");
            sql.push_str(&self.placeholder(bind_index));
            sql.push(')');
        }

        sql.push_str(" ORDER BY issued_at DESC");
        let mut query = sqlx::query_as::<_, CredentialRecord>(&sql);

        if let Some(tenant_id) = filter.tenant_id {
            query = query.bind(tenant_id.to_string());
        }

        if let Some(types) = encoded_credential_types {
            query = query.bind(types);
        }

        if let Some(status) = filter.status {
            query = query.bind(status.as_str());
        }

        if let Some(format) = filter.format {
            query = query.bind(format.as_str());
        }

        if let Some(issuer) = filter.issuer {
            query = query.bind(issuer);
        }

        if let Some(subject) = filter.subject {
            query = query.bind(subject);
        }

        if filter.exclude_expired {
            query = query.bind(time::OffsetDateTime::now_utc().unix_timestamp());
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
            Self::Postgres
        } else if db_url.as_str().starts_with("mysql") {
            Self::MySql
        } else {
            Self::Sqlite
        }
    }
}

async fn insert_credential(
    driver: &Driver,
    tx: &mut Transaction<'_, sqlx::Any>,
    record: &CredentialRecord,
) -> Result<()> {
    sqlx::query(insert_credential_query(driver).for_driver(driver))
        .bind(&record.id)
        .bind(&record.tenant_id)
        .bind(&record.issuer)
        .bind(record.subject.as_deref())
        .bind(record.credential_types.as_str())
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
    let result = sqlx::query(update_credential_query(driver).for_driver(driver))
        .bind(record.issuer.as_str())
        .bind(record.subject.as_deref())
        .bind(record.credential_types.as_str())
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

const SELECT_COLUMNS_POSTGRES: &str = "id, tenant_id, issuer, subject, credential_types::text AS credential_types, \
     format, external_id, status, issued_at, valid_until, CAST(is_revoked AS BIGINT) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS BIGINT) AS payload_encrypted";
const SELECT_COLUMNS_MYSQL: &str = "id, tenant_id, issuer, subject, CAST(credential_types AS CHAR) AS credential_types, \
     format, external_id, status, issued_at, valid_until, CAST(is_revoked AS SIGNED) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS SIGNED) AS payload_encrypted";
const SELECT_COLUMNS_SQLITE: &str = "id, tenant_id, issuer, subject, CAST(credential_types AS TEXT) AS credential_types, \
     format, external_id, status, issued_at, valid_until, CAST(is_revoked AS INTEGER) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS INTEGER) AS payload_encrypted";

static FIND_CREDENTIAL_POSTGRES: Query = Query::new(
    "SELECT id, tenant_id, issuer, subject, credential_types::text AS credential_types, format, \
     external_id, status, issued_at, valid_until, CAST(is_revoked AS BIGINT) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS BIGINT) AS payload_encrypted \
     FROM credentials WHERE id = $1 AND tenant_id = $2",
);
static FIND_CREDENTIAL_MYSQL: Query = Query::new(
    "SELECT id, tenant_id, issuer, subject, CAST(credential_types AS CHAR) AS credential_types, \
     format, external_id, status, issued_at, valid_until, CAST(is_revoked AS SIGNED) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS SIGNED) AS payload_encrypted \
     FROM credentials WHERE id = $1 AND tenant_id = $2",
);
static FIND_CREDENTIAL_SQLITE: Query = Query::new(
    "SELECT id, tenant_id, issuer, subject, CAST(credential_types AS TEXT) AS credential_types, \
     format, external_id, status, issued_at, valid_until, CAST(is_revoked AS INTEGER) AS is_revoked, \
     status_location, status_index, raw_credential, \
     CAST(payload_encrypted AS INTEGER) AS payload_encrypted \
     FROM credentials WHERE id = $1 AND tenant_id = $2",
);

static INSERT_CREDENTIAL_POSTGRES: Query = Query::new(
    "INSERT INTO credentials \
     (id, tenant_id, issuer, subject, credential_types, format, external_id, status, \
      issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
      payload_encrypted) \
     VALUES ($1, $2, $3, $4, CAST($5 AS JSONB), $6, $7, $8, $9, $10, CAST($11 AS BOOLEAN), \
     $12, $13, $14, CAST($15 AS BOOLEAN))",
);
static INSERT_CREDENTIAL_MYSQL: Query = Query::new(
    "INSERT INTO credentials \
     (id, tenant_id, issuer, subject, credential_types, format, external_id, status, \
      issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
      payload_encrypted) \
     VALUES ($1, $2, $3, $4, CAST($5 AS JSON), $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
);
static INSERT_CREDENTIAL_SQLITE: Query = Query::new(
    "INSERT INTO credentials \
     (id, tenant_id, issuer, subject, credential_types, format, external_id, status, \
      issued_at, valid_until, is_revoked, status_location, status_index, raw_credential, \
      payload_encrypted) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
);

static UPDATE_CREDENTIAL_POSTGRES: Query = Query::new(
    "UPDATE credentials SET \
     issuer = $1, subject = $2, credential_types = CAST($3 AS JSONB), format = $4, \
     external_id = $5, status = $6, issued_at = $7, valid_until = $8, \
     is_revoked = CAST($9 AS BOOLEAN), status_location = $10, status_index = $11, \
     raw_credential = $12, payload_encrypted = CAST($13 AS BOOLEAN) \
     WHERE id = $14 AND tenant_id = $15",
);
static UPDATE_CREDENTIAL_MYSQL: Query = Query::new(
    "UPDATE credentials SET \
     issuer = $1, subject = $2, credential_types = CAST($3 AS JSON), format = $4, \
     external_id = $5, status = $6, issued_at = $7, valid_until = $8, is_revoked = $9, \
     status_location = $10, status_index = $11, raw_credential = $12, payload_encrypted = $13 \
     WHERE id = $14 AND tenant_id = $15",
);
static UPDATE_CREDENTIAL_SQLITE: Query = Query::new(
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

fn compact_plaintext_in_place(
    buffer: &mut Vec<u8>,
    plaintext_offset: usize,
    plaintext_len: usize,
) -> Result<()> {
    let end = plaintext_offset + plaintext_len;
    if end > buffer.len() {
        return Err(Error::InvalidData(
            "decrypted plaintext is outside source buffer".to_string(),
        ));
    }

    if plaintext_offset > 0 {
        buffer.copy_within(plaintext_offset..end, 0);
    }
    buffer.truncate(plaintext_len);
    Ok(())
}

fn select_columns_for_driver(driver: &Driver) -> &'static str {
    match driver {
        Driver::Postgres => SELECT_COLUMNS_POSTGRES,
        Driver::MySql => SELECT_COLUMNS_MYSQL,
        Driver::Sqlite => SELECT_COLUMNS_SQLITE,
    }
}

fn find_credential_query(driver: &Driver) -> &'static Query {
    match driver {
        Driver::Postgres => &FIND_CREDENTIAL_POSTGRES,
        Driver::MySql => &FIND_CREDENTIAL_MYSQL,
        Driver::Sqlite => &FIND_CREDENTIAL_SQLITE,
    }
}

fn insert_credential_query(driver: &Driver) -> &'static Query {
    match driver {
        Driver::Postgres => &INSERT_CREDENTIAL_POSTGRES,
        Driver::MySql => &INSERT_CREDENTIAL_MYSQL,
        Driver::Sqlite => &INSERT_CREDENTIAL_SQLITE,
    }
}

fn update_credential_query(driver: &Driver) -> &'static Query {
    match driver {
        Driver::Postgres => &UPDATE_CREDENTIAL_POSTGRES,
        Driver::MySql => &UPDATE_CREDENTIAL_MYSQL,
        Driver::Sqlite => &UPDATE_CREDENTIAL_SQLITE,
    }
}

fn append_json_bind_expr(sql: &mut String, driver: &Driver, placeholder: &str) {
    match driver {
        Driver::Postgres => {
            sql.push_str("CAST(");
            sql.push_str(placeholder);
            sql.push_str(" AS JSONB)");
        }
        Driver::MySql => {
            sql.push_str("CAST(");
            sql.push_str(placeholder);
            sql.push_str(" AS JSON)");
        }
        Driver::Sqlite => sql.push_str(placeholder),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use cloud_wallet_kms::provider::LocalProvider;

    fn sample_credential(tenant_id: Uuid) -> Credential {
        Credential {
            id: Uuid::new_v4(),
            tenant_id,
            issuer: "https://issuer.example".to_string(),
            subject: Some("did:example:alice".to_string()),
            credential_types: serde_json::json!(["VerifiableCredential", "UniversityDegree"]),
            format: CredentialFormat::SdJwtVc,
            external_id: Some("external-1".to_string()),
            status: CredentialStatus::Active,
            issued_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap()
                .into(),
            valid_until: Some(
                time::OffsetDateTime::from_unix_timestamp(2_000_000_000)
                    .unwrap()
                    .into(),
            ),
            is_revoked: false,
            status_location: None,
            status_index: Some(12),
            raw_credential: b"raw-vc-payload".to_vec().into_boxed_slice(),
        }
    }

    #[test]
    fn rewrites_postgres_bindings_to_question_marks() {
        let sql = "SELECT * FROM credentials WHERE id = $1 AND tenant_id = $2";
        assert_eq!(
            rewrite_to_positional(sql).as_ref(),
            "SELECT * FROM credentials WHERE id = ? AND tenant_id = ?"
        );
    }

    #[tokio::test]
    async fn sqlite_crud_roundtrip() {
        sqlx::any::install_default_drivers();

        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let repo: SqlRepository<LocalProvider> = SqlRepository::new(pool.clone());
        repo.init_schema().await.unwrap();

        let tenant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id, name) VALUES (?, ?)")
            .bind(tenant_id.to_string())
            .bind("Tenant A")
            .execute(&pool)
            .await
            .unwrap();

        let credential = sample_credential(tenant_id);
        repo.upsert(credential.clone()).await.unwrap();

        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();
        assert_eq!(found.id, credential.id);
        assert_eq!(found.raw_credential, credential.raw_credential);

        let listed = repo
            .list(CredentialFilter {
                tenant_id: Some(tenant_id),
                format: Some(CredentialFormat::SdJwtVc),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        repo.delete(credential.id, tenant_id).await.unwrap();
        assert!(repo.find_by_id(credential.id, tenant_id).await.is_err());
    }

    #[tokio::test]
    async fn sqlite_with_cipher_roundtrip() {
        sqlx::any::install_default_drivers();

        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let cipher = LocalProvider::new();
        let repo = SqlRepository::with_cipher(pool.clone(), cipher);
        repo.init_schema().await.unwrap();

        let tenant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO tenants (id, name) VALUES (?, ?)")
            .bind(tenant_id.to_string())
            .bind("Tenant A")
            .execute(&pool)
            .await
            .unwrap();

        let credential = sample_credential(tenant_id);
        repo.upsert(credential.clone()).await.unwrap();

        let found = repo.find_by_id(credential.id, tenant_id).await.unwrap();
        assert_eq!(found.raw_credential, credential.raw_credential);
    }
}
