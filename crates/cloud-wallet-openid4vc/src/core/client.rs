use std::{sync::Arc, time::Duration};

use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::{Jitter, RetryTransientMiddleware};
use url::Url;

use crate::errors::{Error, Result};

const HTTP_MAX_RETRIES: u32 = 3;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;

/// Configuration for the OID4VC client.
///
/// # Security
///
/// - Outbound requests are HTTPS-only and not configurable.
/// - For testing purposes, hostname validation can be temporarily disabled via
///   `accept_untrusted_hosts(true)`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The wallet's OAuth 2.0 `client_id` as registered at the issuer AS.
    pub client_id: String,
    /// The redirect URI registered with the issuer AS.
    pub redirect_uri: Url,
    /// Total timeout for each request.
    pub timeout: Duration,
    /// Optional user-agent value to send with every request.
    pub user_agent: Option<String>,
    /// Accept untrusted hosts (testing only).
    ///
    /// **WARNING**: This bypasses TLS certificate validation and HTTPS enforcement.
    /// Only use in test environments with mock servers. Never enable in production.
    pub accept_untrusted_hosts: bool,
    /// Use system proxy configuration discovered by the HTTP client.
    pub use_system_proxy: bool,
}

impl Config {
    /// Creates a new configuration with the given client ID and redirect URI.
    ///
    /// Defaults:
    /// - timeout: 10 seconds
    /// - user_agent: None
    /// - accept_untrusted_hosts: false
    pub fn new(client_id: impl Into<String>, redirect_uri: Url) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri,
            timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
            user_agent: None,
            accept_untrusted_hosts: false,
            use_system_proxy: true,
        }
    }

    /// Sets the total request timeout.
    ///
    /// Defaults to 10 seconds.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Sets a custom user-agent header value.
    pub fn user_agent(self, user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: Some(user_agent.into()),
            ..self
        }
    }

    /// Enables or disables accepting untrusted hosts.
    ///
    /// This should only be enabled in test environments.
    pub fn accept_untrusted_hosts(self, accept_untrusted_hosts: bool) -> Self {
        Self {
            accept_untrusted_hosts,
            ..self
        }
    }

    /// Enables or disables system proxy discovery.
    ///
    /// Disabling this is useful in tests and restricted runtime environments
    /// where reading host networking configuration may fail during client setup.
    pub fn use_system_proxy(self, use_system_proxy: bool) -> Self {
        Self {
            use_system_proxy,
            ..self
        }
    }
}

/// Generic client for handling OID4VC flows and HTTP requests.
#[derive(Debug, Clone)]
pub struct OidClient {
    pub(crate) config: Arc<Config>,
    pub(crate) http_client: ClientWithMiddleware,
}

impl OidClient {
    /// Creates a new client with custom HTTP options for the internal request client.
    pub fn new(config: Config) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder()
            .jitter(Jitter::Bounded)
            .build_with_max_retries(HTTP_MAX_RETRIES);

        let mut inner_client_builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .tls_backend_rustls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .tls_danger_accept_invalid_hostnames(config.accept_untrusted_hosts);

        if config.accept_untrusted_hosts {
            inner_client_builder = inner_client_builder.tls_danger_accept_invalid_certs(true);
        }

        if !config.use_system_proxy {
            inner_client_builder = inner_client_builder.no_proxy();
        }

        if let Some(ref user_agent) = config.user_agent {
            inner_client_builder = inner_client_builder.user_agent(user_agent);
        }

        let inner_client = inner_client_builder.build().map_err(Error::other)?;

        let http_client = ClientBuilder::new(inner_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Self {
            config: Arc::new(config),
            http_client,
        })
    }

    /// Returns the underlying HTTP client.
    pub fn http_client(&self) -> &ClientWithMiddleware {
        &self.http_client
    }

    /// Returns the internal configuration that was used to create this client.
    pub fn config(&self) -> &Config {
        &self.config
    }
}
