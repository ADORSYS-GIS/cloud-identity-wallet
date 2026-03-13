//! PostgreSQL-backed credential repository.
//!
//! Implements [`CredentialRepository<StoredCredential>`] — the encrypted
//! storage layer. Compose with [`EncryptingRepository`] to get the
//! plaintext [`CredentialRepository<Credential>`] interface.
//!
//! [`EncryptingRepository`]: crate::encrypted_repository::EncryptingRepository

use sqlx::{PgPool, Row};

use crate::{
    config::PostgresConfig,
    encryption::StoredCredential,
    errors::StoreError,
    models::{CredentialId, CredentialStatus, StatusReference},
    repository::{CredentialFilter, CredentialRepository},
};

/// The embedded migration DDL (run once on startup).
const MIGRATION_SQL: &str = include_str!("../migrations/0001_credentials.sql");

fn storage_err(err: sqlx::Error) -> StoreError {
    StoreError::Storage(Box::new(err))
}

fn status_str(s: &CredentialStatus) -> &'static str {
    match s {
        CredentialStatus::Active => "active",
        CredentialStatus::Revoked => "revoked",
        CredentialStatus::Suspended => "suspended",
    }
}

fn parse_status(s: &str) -> Result<CredentialStatus, sqlx::Error> {
    match s {
        "active" => Ok(CredentialStatus::Active),
        "revoked" => Ok(CredentialStatus::Revoked),
        "suspended" => Ok(CredentialStatus::Suspended),
        other => Err(sqlx::Error::Decode(
            format!("unknown credential status: {other}").into(),
        )),
    }
}

/// Map a Postgres row back to a [`StoredCredential`].
fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredCredential, sqlx::Error> {
    use crate::models::{Binding, CredentialMetadata, CredentialType};

    // Status-list reference — both columns must be present or both absent.
    let status_list_url: Option<String> = row.try_get("status_list_url")?;
    let status_list_index: Option<i64> = row.try_get("status_list_index")?;
    let status_reference = match (status_list_url, status_list_index) {
        (Some(url), Some(index)) => Some(StatusReference {
            status_list_url: url,
            index: index as u64,
        }),
        _ => None,
    };

    // Parse the ID string back into CredentialId
    let id_str: String = row.try_get("id")?;
    let id = CredentialId::try_from(id_str).map_err(|e| sqlx::Error::Decode(e.into()))?;

    Ok(StoredCredential {
        id,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
        credential_type: CredentialType::new(row.try_get::<String, _>("credential_type")?),
        issued_at: row.try_get("issued_at")?,
        expires_at: row.try_get("expires_at")?,
        status: parse_status(&row.try_get::<String, _>("status")?)?,
        status_reference,
        binding: Binding,
        metadata: CredentialMetadata {},
        encrypted_claims: row.try_get("encrypted_claims")?,
        encrypted_dek: row.try_get("encrypted_dek")?,
    })
}

// ── Repository ────────────────────────────────────────────────────────────────

/// PostgreSQL-backed credential storage (encrypted).
///
/// Implements `CredentialRepository<StoredCredential>` — the inner layer.
/// Wrap with [`crate::encrypted_repository::EncryptingRepository`] to expose the plaintext interface.
pub struct PostgresCredentialRepository {
    pool: PgPool,
}

impl PostgresCredentialRepository {
    /// Connect and run the embedded migration DDL.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        sqlx::raw_sql(MIGRATION_SQL)
            .execute(&pool)
            .await
            .map_err(storage_err)?;
        Ok(Self { pool })
    }

    /// Build a repository from a [`PostgresConfig`].
    pub async fn from_config(config: &PostgresConfig) -> Result<Self, StoreError> {
        let pool = PgPool::connect(&config.url).await.map_err(storage_err)?;
        Self::new(pool).await
    }
}

impl CredentialRepository<StoredCredential> for PostgresCredentialRepository {
    async fn store(&self, cred: StoredCredential) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, issuer, subject, credential_type, issued_at, expires_at,
                status, status_list_url, status_list_index,
                encrypted_dek, encrypted_claims
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9,
                $10, $11
            )
            "#,
        )
        .bind(cred.id.as_ref())
        .bind(&cred.issuer)
        .bind(&cred.subject)
        .bind(cred.credential_type.as_ref())
        .bind(cred.issued_at)
        .bind(cred.expires_at)
        .bind(status_str(&cred.status))
        .bind(cred.status_reference.as_ref().map(|s| &s.status_list_url))
        .bind(cred.status_reference.as_ref().map(|s| s.index as i64))
        .bind(&cred.encrypted_dek)
        .bind(&cred.encrypted_claims)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                StoreError::DuplicateId(cred.id.clone())
            }
            _ => storage_err(e),
        })?;

        Ok(())
    }

    async fn find_by_id(&self, id: &CredentialId) -> Result<StoredCredential, StoreError> {
        let row = sqlx::query("SELECT * FROM credentials WHERE id = $1")
            .bind(id.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        match row {
            Some(r) => row_to_stored(&r).map_err(storage_err),
            None => Err(StoreError::NotFound(id.clone())),
        }
    }

    async fn find_all(&self) -> Result<Vec<StoredCredential>, StoreError> {
        let rows = sqlx::query("SELECT * FROM credentials")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        rows.iter()
            .map(|r| row_to_stored(r).map_err(storage_err))
            .collect()
    }

    async fn find_by_filter(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<StoredCredential>, StoreError> {
        // Build a parameterised WHERE clause from whichever filter fields are set.
        let mut conditions: Vec<String> = Vec::new();
        let mut p = 1usize;

        if filter.issuer.is_some() {
            conditions.push(format!("issuer = ${p}"));
            p += 1;
        }
        if filter.subject.is_some() {
            conditions.push(format!("subject = ${p}"));
            p += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${p}"));
            p += 1;
        }
        if filter.credential_type.is_some() {
            conditions.push(format!("credential_type = ${p}"));
            p += 1;
        }
        if filter.active_at.is_some() {
            conditions.push(format!("(expires_at IS NULL OR expires_at > ${p})"));
            p += 1;
        }
        let _ = p;

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!("SELECT * FROM credentials {where_clause}");
        let mut query = sqlx::query(&sql);

        // Bind values in the same order the placeholders were inserted.
        if let Some(ref issuer) = filter.issuer {
            query = query.bind(issuer);
        }
        if let Some(ref subject) = filter.subject {
            query = query.bind(subject);
        }
        if let Some(ref status) = filter.status {
            query = query.bind(status_str(status));
        }
        if let Some(ref cred_type) = filter.credential_type {
            query = query.bind(cred_type.as_ref());
        }
        if let Some(active_at) = filter.active_at {
            query = query.bind(active_at);
        }

        let rows = query.fetch_all(&self.pool).await.map_err(storage_err)?;
        rows.iter()
            .map(|r| row_to_stored(r).map_err(storage_err))
            .collect()
    }

    async fn update(&self, cred: StoredCredential) -> Result<(), StoreError> {
        let result = sqlx::query(
            r#"
            UPDATE credentials SET
                issuer            = $2,
                subject           = $3,
                credential_type   = $4,
                issued_at         = $5,
                expires_at        = $6,
                status            = $7,
                status_list_url   = $8,
                status_list_index = $9,
                encrypted_dek     = $10,
                encrypted_claims  = $11
            WHERE id = $1
            "#,
        )
        .bind(cred.id.as_ref())
        .bind(&cred.issuer)
        .bind(&cred.subject)
        .bind(cred.credential_type.as_ref())
        .bind(cred.issued_at)
        .bind(cred.expires_at)
        .bind(status_str(&cred.status))
        .bind(cred.status_reference.as_ref().map(|s| &s.status_list_url))
        .bind(cred.status_reference.as_ref().map(|s| s.index as i64))
        .bind(&cred.encrypted_dek)
        .bind(&cred.encrypted_claims)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        if result.rows_affected() == 0 {
            Err(StoreError::NotFound(cred.id))
        } else {
            Ok(())
        }
    }

    async fn delete(&self, id: &CredentialId) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        if result.rows_affected() == 0 {
            Err(StoreError::NotFound(id.clone()))
        } else {
            Ok(())
        }
    }
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(all(feature = "postgres", feature = "encryption"))]
mod tests {
    use super::*;
    use crate::{
        encrypted_repository::EncryptingRepository,
        encryption::Kek,
        models::{Binding, Claims, Credential, CredentialMetadata, CredentialType},
        repository::CredentialRepository,
    };
    use serde_json::json;
    use std::env;
    use time::{Duration, OffsetDateTime};

    async fn setup() -> Option<EncryptingRepository<PostgresCredentialRepository>> {
        let db_url = env::var("DATABASE_URL").ok()?;
        let config = PostgresConfig { url: db_url };
        let backend = PostgresCredentialRepository::from_config(&config)
            .await
            .ok()?;
        let kek = Kek::generate().ok()?;
        Some(EncryptingRepository::new(backend, kek))
    }

    fn make_credential() -> Credential {
        Credential::new(
            "https://issuer.example.com",
            "user-1234",
            CredentialType::new("https://credentials.example.com/id"),
            Claims::new(json!({ "given_name": "Alice", "family_name": "Smith" })),
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            None,
            Binding,
            CredentialMetadata {},
        )
        .expect("valid test credential")
    }

    #[tokio::test]
    async fn postgres_encrypted_crud() {
        let Some(repo) = setup().await else {
            println!("Skipping Postgres integration test: DATABASE_URL not set");
            return;
        };

        let cred = make_credential();
        let id = cred.id.clone();

        // Store (encrypted)
        repo.store(cred.clone()).await.unwrap();

        // Retrieve (decrypted transparently)
        let found = repo.find_by_id(&id).await.unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.issuer, "https://issuer.example.com");
        assert_eq!(found.claims["given_name"], "Alice");

        // Update
        let mut updated = repo.find_by_id(&id).await.unwrap();
        updated.issuer = "https://new-issuer.example.com".into();
        repo.update(updated).await.unwrap();
        assert_eq!(
            repo.find_by_id(&id).await.unwrap().issuer,
            "https://new-issuer.example.com"
        );

        // Delete
        repo.delete(&id).await.unwrap();
        assert!(matches!(
            repo.find_by_id(&id).await,
            Err(StoreError::NotFound(_))
        ));
    }
}
