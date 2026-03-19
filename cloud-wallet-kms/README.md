# Cloud Wallet KMS

[![CI](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml)
[![GitHub](https://img.shields.io/badge/repo-cloud--wallet--kms-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![Rust](https://img.shields.io/badge/msrv-1.92-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![license](https://shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

A key management library for envelope encryption in the Cloud Identity Wallet ecosystem.

## Architecture

The library follows a standard envelope-encryption model:

1. A Master Key (managed locally for `LocalProvider`, or in AWS KMS for `AwsProvider`) protects a Data Encryption Key (DEK). A custom provider can be implemented to support other key management systems.
2. The encrypted DEK is stored via a `Storage` backend.
3. Payload encryption/decryption uses the plaintext DEK.

## Feature Flags

Default features: `local-kms`, `memory-backend`.

- `local-kms`: Enables `provider::LocalProvider` for local key management.
- `aws-kms`: Enables `provider::AwsProvider` which uses AWS KMS for master key and data encryption key lifecycles.
- `memory-backend`: Enables `storage::InMemoryBackend`.
- `sqlite`: Uses SQLite database for storing Data encryption keys.
- `postgres`: Uses PostgreSQL database for storing Data encryption keys.
- `mysql`: Uses MySQL database for storing Data encryption keys.

## Installation

Default setup (local provider + in-memory storage):

```toml
[dependencies]
cloud-wallet-kms = "0.1"
```

AWS + PostgresSQL example:

```toml
[dependencies]
cloud-wallet-kms = { version = "0.1", default-features = false, features = ["aws-kms", "postgres"] }
```

## Quick Start (Local Provider)

```rust
use cloud_wallet_kms::provider::{LocalProvider, Provider};

async fn roundtrip() -> cloud_wallet_kms::Result<()> {
    let provider = LocalProvider::new();
    let aad = b"tenant:acme";
    let mut payload = b"secret payload".to_vec();

    provider.encrypt(aad, &mut payload).await?;
    let plaintext = provider.decrypt(aad, &mut payload).await?;

    assert_eq!(plaintext, b"secret payload");
    Ok(())
}

fn main() {}
```

## AWS KMS Provider

```rust,ignore
use aws_config::{BehaviorVersion, Region};
use cloud_wallet_kms::provider::{AwsProvider, Provider};
use cloud_wallet_kms::storage::InMemoryBackend;

async fn aws_roundtrip() -> cloud_wallet_kms::Result<()> {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .load()
        .await;

    let provider = AwsProvider::new(&config, "server.example.com", InMemoryBackend::new())
        .with_encryption_context("tenant", "acme");

    let aad = b"credential:issue";
    let mut payload = b"sensitive value".to_vec();

    provider.encrypt(aad, &mut payload).await?;
    let plaintext = provider.decrypt(aad, &mut payload).await?;

    assert_eq!(plaintext, b"sensitive value");
    Ok(())
}
```

## SQLite Storage Backend

`SqlxBackend` works with SQLite, PostgreSQL, and MySQL (via feature flags).

```rust,ignore
use cloud_wallet_kms::storage::SqlxBackend;
use sqlx::any::AnyPoolOptions;

async fn setup_storage() -> cloud_wallet_kms::Result<SqlxBackend> {
    sqlx::any::install_default_drivers();

    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await?;

    let storage = SqlxBackend::new(pool);
    storage.init_schema().await?;

    Ok(storage)
}
```

## Security Notes

`LocalProvider` is intended for development/testing and keeps key material local.

## Testing

Run default-feature tests:

```bash
cargo test -p cloud-wallet-kms
```

Run full feature matrix:

```bash
cargo test -p cloud-wallet-kms --all-features
```

Some integration tests use Testcontainers and require a working Docker environment.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT license](../LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
