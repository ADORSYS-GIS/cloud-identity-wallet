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
    encryption::{EncryptedPayload, StoredCredential},
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
///
/// All columns are read by name — the mapping stays in one place and matches
/// exactly what the INSERT/UPDATE writes; nothing is hardcoded in each method.
fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredCredential, sqlx::Error> {
    let format: String = row.try_get("format")?;

    // Reconstruct the format-aware encrypted payload.
    // Each variant reads only its own plaintext column and the shared encrypted BYTEA.
    let encrypted_payload = match format.as_str() {
        "dc+sd-jwt" => EncryptedPayload::DcSdJwt {
            vct: row.try_get("vct")?,
            encrypted_token: row.try_get("encrypted_payload")?,
        },
        "mso_mdoc" => EncryptedPayload::MsoMdoc {
            doc_type: row.try_get("doc_type")?,
            encrypted_data: row.try_get("encrypted_payload")?,
        },
        "jwt_vc_json" => EncryptedPayload::JwtVcJson {
            credential_type: {
                let json_str: String = row.try_get("credential_type")?;
                serde_json::from_str(&json_str).map_err(|e| sqlx::Error::Decode(e.into()))?
            },
            encrypted_token: row.try_get("encrypted_payload")?,
        },
        other => {
            return Err(sqlx::Error::Decode(
                format!("unknown credential format: {other}").into(),
            ));
        }
    };

    // Status-list reference — both columns must be present or both absent.
    let status_list_url: Option<String> = row.try_get("status_list_url")?;
    let status_list_index: Option<i64> = row.try_get("status_list_index")?;
    let status_reference = match (status_list_url, status_list_index) {
        (Some(url), Some(index)) => Some(StatusReference {
            url,
            index: index as u64,
        }),
        _ => None,
    };

    Ok(StoredCredential {
        id: row.try_get("id")?,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
        issued_at: row.try_get("issued_at")?,
        expires_at: row.try_get("expires_at")?,
        credential_configuration_id: row.try_get("credential_configuration_id")?,
        status: parse_status(&row.try_get::<String, _>("status")?)?,
        status_reference,
        encrypted_payload,
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
        // Derive the format-specific plaintext columns and the encrypted BYTEA.
        let (format, vct, doc_type, credential_type_json, encrypted_payload) =
            stored_payload_parts(&cred)?;

        sqlx::query(
            r#"
            INSERT INTO credentials (
                id, issuer, subject, issued_at, expires_at,
                credential_configuration_id, status, format,
                vct, doc_type, credential_type,
                status_list_url, status_list_index,
                encrypted_dek, encrypted_payload
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9, $10, $11,
                $12, $13,
                $14, $15
            )
            "#,
        )
        .bind(&cred.id)
        .bind(&cred.issuer)
        .bind(&cred.subject)
        .bind(cred.issued_at)
        .bind(cred.expires_at)
        .bind(&cred.credential_configuration_id)
        .bind(status_str(&cred.status))
        .bind(&format)
        .bind(&vct)
        .bind(&doc_type)
        .bind(&credential_type_json)
        .bind(cred.status_reference.as_ref().map(|s| &s.url))
        .bind(cred.status_reference.as_ref().map(|s| s.index as i64))
        .bind(&cred.encrypted_dek)
        .bind(&encrypted_payload)
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
            .bind(id)
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
        // Parameters are numbered sequentially — the same order as the binds below.
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
        if filter.credential_configuration_id.is_some() {
            conditions.push(format!("credential_configuration_id = ${p}"));
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
        if let Some(ref cfg_id) = filter.credential_configuration_id {
            query = query.bind(cfg_id);
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
        let (format, vct, doc_type, credential_type_json, encrypted_payload) =
            stored_payload_parts(&cred)?;

        let result = sqlx::query(
            r#"
            UPDATE credentials SET
                issuer                      = $2,
                subject                     = $3,
                issued_at                   = $4,
                expires_at                  = $5,
                credential_configuration_id = $6,
                status                      = $7,
                format                      = $8,
                vct                         = $9,
                doc_type                    = $10,
                credential_type             = $11,
                status_list_url             = $12,
                status_list_index           = $13,
                encrypted_dek               = $14,
                encrypted_payload           = $15
            WHERE id = $1
            "#,
        )
        .bind(&cred.id)
        .bind(&cred.issuer)
        .bind(&cred.subject)
        .bind(cred.issued_at)
        .bind(cred.expires_at)
        .bind(&cred.credential_configuration_id)
        .bind(status_str(&cred.status))
        .bind(&format)
        .bind(&vct)
        .bind(&doc_type)
        .bind(&credential_type_json)
        .bind(cred.status_reference.as_ref().map(|s| &s.url))
        .bind(cred.status_reference.as_ref().map(|s| s.index as i64))
        .bind(&cred.encrypted_dek)
        .bind(&encrypted_payload)
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
        sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
/// The format-specific columns extracted from a [`StoredCredential`].
/// `(format_str, vct, doc_type, credential_type_json, encrypted_bytes)`
type TypeParts = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<u8>,
);

/// Extract the columns that differ per format from a [`StoredCredential`].
///
/// Returns `(format_str, vct, doc_type, credential_type_json, encrypted_bytes)`.
/// Columns not applicable to the current format are `None`.
fn stored_payload_parts(cred: &StoredCredential) -> Result<TypeParts, StoreError> {
    match &cred.encrypted_payload {
        EncryptedPayload::DcSdJwt {
            vct,
            encrypted_token,
        } => Ok((
            "dc+sd-jwt".into(),
            Some(vct.clone()),
            None,
            None,
            encrypted_token.clone(),
        )),
        EncryptedPayload::MsoMdoc {
            doc_type,
            encrypted_data,
        } => Ok((
            "mso_mdoc".into(),
            None,
            Some(doc_type.clone()),
            None,
            encrypted_data.clone(),
        )),
        EncryptedPayload::JwtVcJson {
            credential_type,
            encrypted_token,
        } => {
            let json = serde_json::to_string(credential_type)
                .map_err(|e| StoreError::Storage(Box::new(e)))?;
            Ok((
                "jwt_vc_json".into(),
                None,
                None,
                Some(json),
                encrypted_token.clone(),
            ))
        }
    }
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "encryption")]
mod tests {
    use super::*;
    use crate::{
        encrypted_repository::EncryptingRepository,
        encryption::Kek,
        models::{Credential, CredentialPayload, SdJwtCredential},
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
            OffsetDateTime::now_utc(),
            Some(OffsetDateTime::now_utc() + Duration::days(365)),
            "identity_credential",
            CredentialPayload::DcSdJwt(SdJwtCredential {
                token: "header.payload.sig~disclosure~".into(),
                vct: "https://credentials.example.com/id".into(),
                claims: json!({ "given_name": "Alice", "family_name": "Smith" }),
            }),
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
        assert_eq!(found.credential.claims().unwrap()["given_name"], "Alice");

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
