use std::collections::HashMap;

use config::{builder::DefaultState, Config as ConfigLib, ConfigBuilder, ConfigError, Environment};
use serde::{Deserialize, Serialize};

/// Application configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub metadata: MetadataConfig,
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// Metadata resolution configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataConfig {
    /// Cache TTL in seconds for issuer and AS metadata.
    ///
    /// Defaults to 300 (5 minutes).
    pub cache_ttl_secs: u64,

    /// Maximum number of entries in each metadata cache.
    ///
    /// Defaults to 1000.
    pub cache_max_entries: u64,

    /// HTTP timeout in seconds for metadata requests.
    ///
    /// Defaults to 10 seconds.
    pub http_timeout_secs: u64,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 300,
            cache_max_entries: 1000,
            http_timeout_secs: 10,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_with_sources(None)
    }

    fn load_with_sources(env_vars: Option<HashMap<String, String>>) -> Result<Self, ConfigError> {
        let mut builder = Self::set_defaults()?;
        // If env_vars is provided, we use it instead of system environment
        // This is to avoid systems variables pollution across tests
        if let Some(vars) = env_vars {
            for (key, value) in vars {
                builder = builder.set_override(&key, value)?;
            }
        } else {
            // Use system environment variables
            // Should be in the format APP_SERVER__HOST or APP_SERVER__PORT
            builder = builder.add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            );
        }

        builder.build()?.try_deserialize()
    }

    /// Set default values for the configuration.
    /// This is used when no environment variables or config file are provided
    fn set_defaults() -> Result<ConfigBuilder<DefaultState>, ConfigError> {
        ConfigLib::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default("metadata.cache_ttl_secs", 300)?
            .set_default("metadata.cache_max_entries", 1000)?
            .set_default("metadata.http_timeout_secs", 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_config() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_env_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert("server.host".to_string(), "0.0.0.0".to_string());
        env_vars.insert("server.port".to_string(), "443".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
    }

    #[test]
    fn test_partial_env_override() {
        let mut env_vars = HashMap::new();
        // We just override the host
        env_vars.insert("server.host".to_string(), "192.168.1.1".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "192.168.1.1");
        // The other values should use default
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn test_metadata_config_defaults() {
        let config = Config::load().expect("Failed to load config");

        assert_eq!(config.metadata.cache_ttl_secs, 300);
        assert_eq!(config.metadata.cache_max_entries, 1000);
        assert_eq!(config.metadata.http_timeout_secs, 10);
    }

    #[test]
    fn test_metadata_config_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert("metadata.cache_ttl_secs".to_string(), "600".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.metadata.cache_ttl_secs, 600);
        assert_eq!(config.metadata.cache_max_entries, 1000);
    }
}
