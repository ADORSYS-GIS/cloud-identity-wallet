use std::collections::HashMap;

use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment, builder::DefaultState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
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
            .set_default("server.port", 3000)
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
}
