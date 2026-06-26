use std::{collections::HashMap, path::PathBuf, time::Duration};

use cloud_wallet_openid4vc::formats::mdoc::RevocationPolicy;
use cloud_wallet_openid4vc::oid4vp::request_object::DiscoveryMode;
use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment, builder::DefaultState};
use redis::{
    Client as RedisClient, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_with::{PickFirst, StringWithSeparator, formats::CommaSeparator, serde_as};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub redis: RedisConfig,
    pub database: DatabaseConfig,
    pub oid4vc: Oid4vcConfig,
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

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Oid4vcConfig {
    pub client_id: String,
    pub redirect_uri: Url,
    pub use_system_proxy: bool,
    #[serde_as(as = "PickFirst<(StringWithSeparator::<CommaSeparator, String>, Vec<_>)>")]
    pub preferred_display_locales: Vec<String>,
    #[serde(default)]
    pub revocation_policy: RevocationPolicy,
    #[serde(default)]
    pub discovery_mode: DiscoveryMode,
    pub root_truststore_dir: Option<PathBuf>,
}

impl RedisConfig {
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

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_with_sources(None)
    }

    fn load_with_sources(env_vars: Option<HashMap<String, String>>) -> Result<Self, ConfigError> {
        let mut builder = Self::set_defaults()?;
        if let Some(vars) = env_vars {
            for (key, value) in vars {
                builder = builder.set_override(&key, value)?;
            }
        } else {
            builder = builder.add_source(
                Environment::with_prefix("APP")
                    .prefix_separator("_")
                    .separator("__"),
            );
        }

        builder.build()?.try_deserialize()
    }

    fn set_defaults() -> Result<ConfigBuilder<DefaultState>, ConfigError> {
        Ok(ConfigLib::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default("redis.uri", "redis://127.0.0.1:6379?protocol=resp3")?
            .set_default("database.url", "sqlite::memory:")?
            .set_default("oid4vc.client_id", "cloud-identity-wallet")?
            .set_default(
                "oid4vc.redirect_uri",
                "http://localhost:3000/api/v1/issuance/callback",
            )?
            .set_default("oid4vc.use_system_proxy", true)?
            .set_default("oid4vc.preferred_display_locales", vec!["en"])?
            .set_default("oid4vc.revocation_policy", "soft_fail")?
            .set_default("oid4vc.discovery_mode", "static")?)
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
        assert_eq!(config.oid4vc.preferred_display_locales, vec!["en"]);
        assert_eq!(config.oid4vc.discovery_mode, DiscoveryMode::Static);
        assert!(config.oid4vc.root_truststore_dir.is_none());
    }

    #[test]
    fn test_preferred_display_locales_csv_string_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert(
            "oid4vc.preferred_display_locales".to_string(),
            "fr,de,en".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(
            config.oid4vc.preferred_display_locales,
            vec!["fr", "de", "en"]
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
    fn test_root_truststore_dir_defaults_to_none() {
        let config = Config::load().expect("Failed to load config");
        assert!(config.oid4vc.root_truststore_dir.is_none());
    }

    #[test]
    fn test_discovery_mode_default_is_static() {
        let config = Config::load().expect("Failed to load config");
        assert_eq!(config.oid4vc.discovery_mode, DiscoveryMode::Static);
    }

    #[test]
    fn test_discovery_mode_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert("oid4vc.discovery_mode".to_string(), "dynamic".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.oid4vc.discovery_mode, DiscoveryMode::Dynamic);
    }

    #[test]
    fn test_partial_env_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert("server.host".to_string(), "192.168.1.1".to_string());

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(config.server.host, "192.168.1.1");
        assert_eq!(config.server.port, 3000);
        assert_eq!(
            config.redis.uri.expose_secret(),
            "redis://127.0.0.1:6379?protocol=resp3"
        );
    }
}
