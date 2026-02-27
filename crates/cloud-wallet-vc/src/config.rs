//! Configuration for the Verifiable Credential crate.

use serde::{Deserialize, Serialize};

/// Configuration for the PostgreSQL repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// The database connection URL.
    pub url: String,
}
