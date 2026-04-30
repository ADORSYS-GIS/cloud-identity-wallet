use std::borrow::Cow;
use std::fmt::Write;
use std::sync::OnceLock;

use sqlx::{AnyPool, ConnectOptions};

/// An SQL database driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    Postgres,
    MySql,
    Sqlite,
}

impl Driver {
    /// Create a new driver from a pool.
    pub fn from_pool(pool: &AnyPool) -> Self {
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
    pub fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres)
    }

    /// Write a bind placeholder into `buf`.
    /// Postgres uses `$N`; MySQL and SQLite use `?`.
    #[inline]
    pub fn write_placeholder(&self, buf: &mut String, index: usize) {
        if self.is_postgres() {
            buf.push('$');
            write!(buf, "{index}").unwrap();
        } else {
            buf.push('?');
        }
    }
}

/// Query wrapper that handles driver-specific placeholder rewriting.
///
/// Postgres uses `$N` placeholders; MySQL and SQLite use `?`.
/// This wrapper automatically rewrites queries to the target driver's format.
pub struct Query {
    raw: &'static str,
    rewritten: OnceLock<String>,
}

impl Query {
    /// Create a new query wrapper from a raw SQL string.
    pub const fn new(raw: &'static str) -> Self {
        Self {
            raw,
            rewritten: OnceLock::new(),
        }
    }

    /// Get the query string for the given driver.
    ///
    /// The query is computed once and cached.
    pub fn for_driver(&self, driver: &Driver) -> &str {
        match driver {
            Driver::Postgres => self.raw,
            Driver::MySql | Driver::Sqlite => self
                .rewritten
                .get_or_init(|| rewrite_to_positional(self.raw).into_owned()),
        }
    }
}

/// Rewrite a query from `$N` placeholders to `?` placeholders.
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
}
