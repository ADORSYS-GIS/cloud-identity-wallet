//! SQL-based implementation of the TenantRepository trait.

use std::sync::OnceLock;

use async_trait::async_trait;
use sqlx::{AnyPool, ConnectOptions};
use time::UtcDateTime;
use uuid::Uuid;

use crate::domain::{
    models::tenants::{RegisterTenantRequest, TenantError, TenantName, TenantResponse},
    ports::TenantRepository,
};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");
static MYSQL_SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/mysql_sqlite");

/// SQL-based tenant repository implementation.
///
/// Supports PostgreSQL, MySQL, and SQLite databases.
#[derive(Debug, Clone)]
pub struct SqlTenantRepository {
    pool: AnyPool,
    driver: Driver,
}

impl SqlTenantRepository {
    /// Creates a new SQL tenant repository with the given connection pool.
    pub fn new(pool: AnyPool) -> Self {
        let driver = Driver::from_pool(&pool);
        Self { pool, driver }
    }

    /// Runs embedded database migrations to ensure required tables exist.
    pub async fn init_schema(&self) -> Result<(), TenantError> {
        match self.driver {
            Driver::Postgres => POSTGRES_MIGRATOR.run(&self.pool).await?,
            _ => MYSQL_SQLITE_MIGRATOR.run(&self.pool).await?,
        }
        Ok(())
    }
}

#[async_trait]
impl TenantRepository for SqlTenantRepository {
    async fn create(&self, request: RegisterTenantRequest) -> Result<TenantResponse, TenantError> {
        let tenant_name = TenantName::new(request.name).map_err(TenantError::InvalidName)?;

        let id = Uuid::new_v4();
        let created_at = UtcDateTime::now();

        sqlx::query(INSERT_TENANT.for_driver(&self.driver))
            .bind(id.to_string())
            .bind(tenant_name.as_str())
            .bind(created_at.unix_timestamp())
            .execute(&self.pool)
            .await?;

        Ok(TenantResponse {
            tenant_id: id.to_string(),
            name: tenant_name.into_inner(),
        })
    }
}

/// Database driver enumeration for SQL dialect handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Driver {
    Postgres,
    MySql,
    Sqlite,
}

impl Driver {
    /// Detect the driver type from the connection pool URL.
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
}

/// SQL query with driver-specific placeholder handling.
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

    /// Returns the query string appropriate for the given driver.
    /// Postgres uses `$N` placeholders; MySQL/SQLite use `?`.
    fn for_driver(&self, driver: &Driver) -> &str {
        match driver {
            Driver::Postgres => self.raw,
            Driver::MySql | Driver::Sqlite => self
                .rewritten
                .get_or_init(|| rewrite_to_positional(self.raw).into_owned()),
        }
    }
}

/// Rewrites Postgres-style `$N` placeholders to `?` for MySQL/SQLite.
fn rewrite_to_positional(sql: &str) -> std::borrow::Cow<'_, str> {
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
    std::borrow::Cow::Owned(result)
}

static INSERT_TENANT: Query =
    Query::new("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_postgres_bindings_to_question_marks() {
        let sql = "INSERT INTO tenants (id, name) VALUES ($1, $2)";
        assert_eq!(
            rewrite_to_positional(sql).as_ref(),
            "INSERT INTO tenants (id, name) VALUES (?, ?)"
        );
    }

    #[test]
    fn query_for_driver_returns_correct_sql() {
        let postgres = Driver::Postgres;
        let mysql = Driver::MySql;

        let query = Query::new("SELECT * FROM tenants WHERE id = $1");

        assert!(query.for_driver(&postgres).contains('$'));
        assert!(!query.for_driver(&postgres).contains('?'));
        assert!(query.for_driver(&mysql).contains('?'));
        assert!(!query.for_driver(&mysql).contains('$'));
    }
}
