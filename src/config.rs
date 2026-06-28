use std::collections::HashMap;
#[cfg(feature = "redis")]
use std::time::Duration;

use cloud_wallet_openid4vc::formats::mdoc::RevocationPolicy;
use config::{Config as ConfigLib, ConfigBuilder, ConfigError, Environment, builder::DefaultState};
#[cfg(feature = "redis")]
use redis::{
    Client as RedisClient, RedisResult,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
#[cfg(any(feature = "redis", test))]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::{PickFirst, StringWithSeparator, formats::CommaSeparator, serde_as};
#[cfg(feature = "redis")]
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub backend: Backend,
    pub server: ServerConfig,
    pub redis: RedisConfig,
    pub database: DatabaseConfig,
    pub kms: KmsConfig,
    pub oid4vci: Oid4vciConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Memory,
    MySql,
    Postgres,
    Sqlite,
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
pub struct KmsConfig {
    pub provider: KmsProviderKind,
    pub aws_region: Option<String>,
    pub aws_kms_key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KmsProviderKind {
    Local,
    Aws,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct Oid4vciConfig {
    pub client_id: String,
    pub redirect_uri: Url,
    pub use_system_proxy: bool,
    /// Locale prefixes tried in order when selecting a credential display entry.
    /// Configurable via `APP_OID4VCI__PREFERRED_DISPLAY_LOCALES=en,fr,de`.
    #[serde_as(as = "PickFirst<(StringWithSeparator::<CommaSeparator, String>, Vec<_>)>")]
    pub preferred_display_locales: Vec<String>,
    /// Paths to DER- or PEM-encoded IACA root certificate files loaded at startup.
    #[serde_as(as = "PickFirst<(StringWithSeparator::<CommaSeparator, String>, Vec<_>)>")]
    pub iaca_root_paths: Vec<String>,
    /// DSC revocation checking policy for mdoc verification.
    /// - `skip`: Bypass revocation checking entirely (offline/test mode)
    /// - `soft_fail`: Reject revoked DSCs, tolerate CRL fetch failures (default)
    /// - `hard_fail`: Reject revoked DSCs or on any CRL fetch/parse failure
    /// Configurable via `APP_OID4VCI__REVOCATION_POLICY=soft_fail`.
    #[serde(default)]
    pub revocation_policy: RevocationPolicy,
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
    #[cfg(feature = "redis")]
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
            .set_default("backend", "memory")?
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 3000)?
            .set_default("redis.uri", "redis://127.0.0.1:6379?protocol=resp3")?
            .set_default("database.url", "sqlite::memory:")?
            .set_default("kms.provider", "local")?
            .set_default("kms.aws_region", Option::<String>::None)?
            .set_default("kms.aws_kms_key_id", Option::<String>::None)?
            .set_default("oid4vci.client_id", "cloud-identity-wallet")?
            .set_default(
                "oid4vci.redirect_uri",
                "http://localhost:3000/api/v1/issuance/callback",
            )?
            .set_default("oid4vci.use_system_proxy", true)?
            .set_default("oid4vci.preferred_display_locales", vec!["en"])?
            .set_default("oid4vci.iaca_root_paths", Vec::<String>::new())?
            .set_default("oid4vci.revocation_policy", "soft_fail")
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
        assert_eq!(config.oid4vci.preferred_display_locales, vec!["en"]);
    }

    #[test]
    fn test_preferred_display_locales_csv_string_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert(
            "oid4vci.preferred_display_locales".to_string(),
            "fr,de,en".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(
            config.oid4vci.preferred_display_locales,
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
    fn test_iaca_root_paths_defaults_to_empty() {
        let config = Config::load().expect("Failed to load config");
        assert!(config.oid4vci.iaca_root_paths.is_empty());
    }

    #[test]
    fn test_iaca_root_paths_csv_string_override() {
        let mut env_vars = HashMap::new();
        env_vars.insert(
            "oid4vci.iaca_root_paths".to_string(),
            "/certs/root1.pem,/certs/root2.der".to_string(),
        );

        let config = Config::load_with_sources(Some(env_vars)).expect("Failed to load config");

        assert_eq!(
            config.oid4vci.iaca_root_paths,
            vec!["/certs/root1.pem", "/certs/root2.der"]
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
