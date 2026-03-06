//! Configuration types for the `cloud-wallet-openid4vc` crate.

use serde::{Deserialize, Serialize};

/// Configuration for the PostgreSQL credential repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// PostgreSQL connection URL, e.g. `postgres://user:password@localhost/dbname`.
    pub url: String,
}
