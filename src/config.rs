use std::{collections::HashMap, time::Duration};

use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment, builder::DefaultState};
use redis::{
    Client as RedisClient, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub redis: RedisConfig,
    pub database: DatabaseConfig,
    pub wallet: WalletConfig,
    pub oid4vci: Oid4vciConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub uri: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: SecretString,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oid4vciConfig {
    pub client_id: String,
    pub redirect_uri: Url,
    pub use_system_proxy: bool,
}

impl RedisConfig {
    /// Establishes a new Redis connection based on the provided URI.
    ///
    /// - To enable TLS, the URI must use the `rediss://` scheme.
    /// - To enable insecure TLS, the URI must use the `rediss://` scheme and end with `/#insecure`.
    /// - To enable RESP3 protocol, the URI must contains the `protocol=resp3` query parameter.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established.
    pub async fn start(
        &self,
    ) -> RedisResult<(ConnectionManager, UnboundedReceiver<redis::PushInfo>)> {
        let client = RedisClient::open(self.uri.expose_secret())?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let config = ConnectionManagerConfig::new()
            .set_number_of_retries(3)
            .set_response_timeout(Some(Duration::from_secs(30)))
            .set_connection_timeout(Some(Duration::from_secs(30)))
            .set_push_sender(tx)
            .set_automatic_resubscription();

        let manager = client.get_connection_manager_with_config(config).await?;
        Ok((manager, rx))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub client_id: String,
    pub redirect_uri: Url,
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
            .set_default("redis.uri", "redis://127.0.0.1:6379?protocol=resp3")?
            .set_default("database.url", "sqlite::memory:")?
            .set_default("wallet.client_id", "cloud-identity-wallet")?
            .set_default(
                "wallet.redirect_uri",
                "http://127.0.0.1:3000/api/v1/issuance/callback",
            )?
            .set_default("oid4vci.client_id", "cloud-identity-wallet")?
            .set_default("oid4vci.redirect_uri", "http://localhost:3000/callback")?
            .set_default("oid4vci.use_system_proxy", true)
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
        assert_eq!(
            config.redis.uri.expose_secret(),
            "redis://127.0.0.1:6379?protocol=resp3"
        );
    }

    #[test]
    fn test_env_config() {
        let mut env_vars = HashMap::new();
        env_vars.insert("server.host".to_string(), "0.0.0.0".to_string());
        env_vars.insert("server.port".to_string(), "443".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 443);
        assert_eq!(
            config.redis.uri.expose_secret(),
            "redis://127.0.0.1:6379?protocol=resp3"
        );
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
        assert_eq!(
            config.redis.uri.expose_secret(),
            "redis://127.0.0.1:6379?protocol=resp3"
        );
    }
}
