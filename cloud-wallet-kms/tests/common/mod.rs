//! Common utilities for integration tests.

#![allow(dead_code)]

use aws_config::SdkConfig;
use aws_sdk_kms::config::Credentials;
use std::sync::OnceLock;
use testcontainers_modules::{
    localstack::LocalStack,
    testcontainers::{ContainerAsync, ImageExt, bollard::Docker, runners::AsyncRunner},
};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Sample plaintext for testing encryption/decryption operations.
pub const SAMPLE_PLAINTEXT: &[u8] = b"Hello, World!";

/// Sample Additional Authenticated Data (AAD).
pub const SAMPLE_AAD: &[u8] = b"some-additional-data";

enum DockerState {
    Unknown,
    Available,
    Unavailable(String),
}

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
static DOCKER_STATE: OnceLock<Mutex<DockerState>> = OnceLock::new();

fn localstack_state() -> &'static Mutex<Option<LocalStackState>> {
    LOCALSTACK.get_or_init(|| Mutex::new(None))
}

fn docker_state() -> &'static Mutex<DockerState> {
    DOCKER_STATE.get_or_init(|| Mutex::new(DockerState::Unknown))
}

async fn check_docker() -> std::result::Result<(), String> {
    let docker = Docker::connect_with_local_defaults()
        .map_err(|error| format!("failed to create a Docker client: {error}"))?;

    docker
        .ping()
        .await
        .map(|_| ())
        .map_err(|error| format!("failed to reach the Docker daemon: {error}"))
}

/// Returns true when the local Docker daemon is reachable.
pub async fn docker_available() -> bool {
    let mut guard = docker_state().lock().await;
    match &*guard {
        DockerState::Available => true,
        DockerState::Unavailable(_) => false,
        DockerState::Unknown => match check_docker().await {
            Ok(()) => {
                *guard = DockerState::Available;
                true
            }
            Err(reason) => {
                eprintln!(
                    "Skipping Docker-backed integration tests because Docker is unavailable: {reason}"
                );
                *guard = DockerState::Unavailable(reason);
                false
            }
        },
    }
}

/// Sets up the test environment with LocalStack.
pub async fn setup() -> Option<SdkConfig> {
    init_tracing();

    if !docker_available().await {
        return None;
    }

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
    Some(create_aws_config(&endpoint).await)
}
