//! PostgreSQL-backed credential repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    credential::{Credential, CredentialFormat, CredentialMetadata, CredentialStatus},
    repository::{CredentialFilter, CredentialRepository, StoreError},
};

/// Converts a [`sqlx`] error into [`StoreError::Storage`].
fn storage_err(err: sqlx::Error) -> StoreError {
    StoreError::Storage(Box::new(err))
}

/// The embedded migration DDL.
const MIGRATION_SQL: &str = include_str!("../migrations/0001_credentials.sql");

/// PostgreSQL-backed implementation of [`CredentialRepository`].
pub struct PostgresCredentialRepository {
    pool: PgPool,
}

impl PostgresCredentialRepository {
    /// Create a repository and ensure the database schema is up to date.
    pub async fn new(pool: PgPool) -> Result<Self, StoreError> {
        sqlx::raw_sql(MIGRATION_SQL)
            .execute(&pool)
            .await
            .map_err(storage_err)?;
        Ok(Self { pool })
    }

    /// Create a repository from configuration.
    pub async fn from_config(config: &crate::config::PostgresConfig) -> Result<Self, StoreError> {
        let pool = PgPool::connect(&config.url).await.map_err(storage_err)?;
        Self::new(pool).await
    }
}

/// Map a `sqlx` Postgres row to a [`Credential`] domain object.
fn row_to_credential(row: &sqlx::postgres::PgRow) -> Result<Credential, sqlx::Error> {
    let format_str: String = row.try_get("format")?;
    let format = format_str
        .parse::<CredentialFormat>()
        .map_err(|e| sqlx::Error::Decode(e.into()))?;

    let status_list_url: Option<String> = row.try_get("status_list_url")?;
    let status_list_index: Option<i32> = row.try_get("status_list_index")?;
    let status = match (status_list_url, status_list_index) {
        (Some(url), Some(idx)) => Some(CredentialStatus {
            status_list_url: url,
            status_list_index: idx as u64,
        }),
        _ => None,
    };

    Ok(Credential {
        id: row.try_get("id")?,
        format,
        raw_credential: row.try_get("raw_credential")?,
        metadata: CredentialMetadata {
            iss: row.try_get("iss")?,
            iat: row.try_get::<DateTime<Utc>, _>("iat")?,
            exp: row.try_get::<Option<DateTime<Utc>>, _>("exp")?,
            sub: row.try_get("sub")?,
            vct: row.try_get("vct")?,
            doctype: row.try_get("doctype")?,
            credential_type: row.try_get("credential_type")?,
            credential_configuration_id: row.try_get("credential_configuration_id")?,
            status,
        },
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
    })
}

#[async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn store(&self, cred: Credential) -> Result<(), StoreError> {
        let (status_url, status_idx) = match &cred.metadata.status {
            Some(s) => (
                Some(s.status_list_url.clone()),
                Some(s.status_list_index as i64),
            ),
            None => (None, None),
        };

        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, format, raw_credential,
                iss, sub, iat, exp,
                vct, doctype, credential_type, credential_configuration_id,
                status_list_url, status_list_index,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3,
                $4, $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13,
                $14, $15
            )
            "#,
        )
        .bind(cred.id)
        .bind(cred.format.to_string())
        .bind(&cred.raw_credential)
        .bind(&cred.metadata.iss)
        .bind(&cred.metadata.sub)
        .bind(cred.metadata.iat)
        .bind(cred.metadata.exp)
        .bind(&cred.metadata.vct)
        .bind(&cred.metadata.doctype)
        .bind(&cred.metadata.credential_type)
        .bind(&cred.metadata.credential_configuration_id)
        .bind(&status_url)
        .bind(status_idx)
        .bind(cred.created_at)
        .bind(cred.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                StoreError::DuplicateId(cred.id)
            }
            _ => storage_err(e),
        })?;

        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Credential, StoreError> {
        let row = sqlx::query("SELECT * FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;

        match row {
            Some(r) => row_to_credential(&r).map_err(storage_err),
            None => Err(StoreError::NotFound(id)),
        }
    }

    async fn find_all(&self) -> Result<Vec<Credential>, StoreError> {
        let rows = sqlx::query("SELECT * FROM credentials")
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        rows.iter()
            .map(|r| row_to_credential(r).map_err(storage_err))
            .collect()
    }

    async fn find_by_filter(
        &self,
        filter: CredentialFilter,
    ) -> Result<Vec<Credential>, StoreError> {
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 1usize;

        macro_rules! push_cond {
            ($col:expr) => {{
                conditions.push(format!("{} = ${}", $col, param_idx));
                param_idx += 1;
            }};
            (opt $col:expr) => {{
                conditions.push(format!("{} = ${}", $col, param_idx));
                param_idx += 1;
            }};
        }

        if filter.format.is_some() {
            push_cond!("format");
        }
        if filter.iss.is_some() {
            push_cond!("iss");
        }
        if filter.vct.is_some() {
            push_cond!("vct");
        }
        if filter.doctype.is_some() {
            push_cond!("doctype");
        }
        if filter.sub.is_some() {
            push_cond!("sub");
        }
        if filter.not_expired_at.is_some() {
            // exp IS NULL (no expiry) OR exp > $N
            conditions.push(format!("(exp IS NULL OR exp > ${})", param_idx));
            param_idx += 1;
        }
        let _ = param_idx; // suppress unused warning

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        let sql = format!("SELECT * FROM credentials {where_clause}");

        // Bind parameters in the same order they were added.
        let mut query = sqlx::query(&sql);
        if let Some(fmt) = &filter.format {
            query = query.bind(fmt.to_string());
        }
        if let Some(iss) = &filter.iss {
            query = query.bind(iss);
        }
        if let Some(vct) = &filter.vct {
            query = query.bind(vct);
        }
        if let Some(doctype) = &filter.doctype {
            query = query.bind(doctype);
        }
        if let Some(sub) = &filter.sub {
            query = query.bind(sub);
        }
        if let Some(not_expired) = filter.not_expired_at {
            query = query.bind(not_expired);
        }

        let rows = query.fetch_all(&self.pool).await.map_err(storage_err)?;
        rows.iter()
            .map(|r| row_to_credential(r).map_err(storage_err))
            .collect()
    }

    async fn update(&self, mut cred: Credential) -> Result<(), StoreError> {
        cred.updated_at = Utc::now();

        let (status_url, status_idx) = match &cred.metadata.status {
            Some(s) => (
                Some(s.status_list_url.clone()),
                Some(s.status_list_index as i64),
            ),
            None => (None, None),
        };

        let result = sqlx::query(
            r#"
            UPDATE credentials SET
                format                      = $2,
                raw_credential              = $3,
                iss                         = $4,
                sub                         = $5,
                iat                         = $6,
                exp                         = $7,
                vct                         = $8,
                doctype                     = $9,
                credential_type             = $10,
                credential_configuration_id = $11,
                status_list_url             = $12,
                status_list_index           = $13,
                updated_at                  = $14
            WHERE id = $1
            "#,
        )
        .bind(cred.id)
        .bind(cred.format.to_string())
        .bind(&cred.raw_credential)
        .bind(&cred.metadata.iss)
        .bind(&cred.metadata.sub)
        .bind(cred.metadata.iat)
        .bind(cred.metadata.exp)
        .bind(&cred.metadata.vct)
        .bind(&cred.metadata.doctype)
        .bind(&cred.metadata.credential_type)
        .bind(&cred.metadata.credential_configuration_id)
        .bind(&status_url)
        .bind(status_idx)
        .bind(cred.updated_at)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        if result.rows_affected() == 0 {
            Err(StoreError::NotFound(cred.id))
        } else {
            Ok(())
        }
    }

    async fn delete(&self, id: Uuid) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StoreError::Storage(Box::new(e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::{CredentialFormat, CredentialMetadata};
    use chrono::Utc;
    use std::env;

    async fn setup_repo() -> Option<PostgresCredentialRepository> {
        let db_url = env::var("DATABASE_URL").ok()?;
        let config = crate::config::PostgresConfig { url: db_url };
        PostgresCredentialRepository::from_config(&config)
            .await
            .ok()
    }

    #[tokio::test]
    async fn test_postgres_crud() {
        let Some(repo) = setup_repo().await else {
            println!("Skipping Postgres integration test: DATABASE_URL not set");
            return;
        };

        let id = Uuid::new_v4();
        let cred = Credential {
            id,
            format: CredentialFormat::DcSdJwt,
            raw_credential: "raw".to_string(),
            metadata: CredentialMetadata {
                iss: "https://issuer.com".to_string(),
                iat: Utc::now(),
                exp: None,
                sub: None,
                vct: None,
                doctype: None,
                credential_type: None,
                credential_configuration_id: None,
                status: None,
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Store
        repo.store(cred.clone()).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(id).await.unwrap();
        assert_eq!(found.id, id);

        // Update
        let mut to_update = found;
        to_update.metadata.iss = "https://new.com".to_string();
        repo.update(to_update).await.unwrap();

        let updated = repo.find_by_id(id).await.unwrap();
        assert_eq!(updated.metadata.iss, "https://new.com");

        // Find all
        let all = repo.find_all().await.unwrap();
        assert!(all.iter().any(|c| c.id == id));

        // Delete
        repo.delete(id).await.unwrap();
        let result = repo.find_by_id(id).await;
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }
}
