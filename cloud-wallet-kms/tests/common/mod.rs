//! Common utilities for integration tests.

#![allow(dead_code)]

use aws_config::SdkConfig;
use aws_sdk_kms::config::Credentials;
use std::sync::OnceLock;
use testcontainers_modules::{
    localstack::LocalStack,
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Sample plaintext for testing encryption/decryption operations.
pub const SAMPLE_PLAINTEXT: &[u8] = b"Hello, World!";

/// Sample Additional Authenticated Data (AAD).
pub const SAMPLE_AAD: &[u8] = b"some-additional-data";

/// Initialize tracing for tests.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .with_test_writer()
        .try_init();
}

/// Helper to configure AWS SDK for LocalStack.
async fn create_aws_config(endpoint: &str) -> SdkConfig {
    use aws_config::BehaviorVersion;

    let credentials = Credentials::new("test", "test", None, None, "localstack");
    aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .endpoint_url(endpoint)
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await
}

struct LocalStackState {
    _container: ContainerAsync<LocalStack>,
    endpoint: String,
}

static LOCALSTACK: OnceLock<Mutex<Option<LocalStackState>>> = OnceLock::new();

fn localstack_state() -> &'static Mutex<Option<LocalStackState>> {
    LOCALSTACK.get_or_init(|| Mutex::new(None))
}

/// Sets up the test environment with LocalStack.
pub async fn setup() -> SdkConfig {
    init_tracing();

    let endpoint = {
        let mut guard = localstack_state().lock().await;
        if guard.is_none() {
            let localstack = LocalStack::default()
                .with_env_var("SERVICES", "kms")
                .with_tag("4.14")
                .start()
                .await
                .expect("Failed to start LocalStack");

            let port = localstack.get_host_port_ipv4(4566).await.unwrap();
            let host = localstack.get_host().await.unwrap();
            let endpoint = format!("http://{host}:{port}");

            *guard = Some(LocalStackState {
                _container: localstack,
                endpoint,
            });
        }
        guard
            .as_ref()
            .expect("LocalStack state should be initialized")
            .endpoint
            .clone()
    };
    create_aws_config(&endpoint).await
}
