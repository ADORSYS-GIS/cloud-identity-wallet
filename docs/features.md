# Cargo Feature Matrix

The server selects infrastructure backends with Cargo features and validates the matching runtime configuration at startup.

## Feature Flags

| Feature     | Default | Enables                                                                                                                         |
| ----------- | ------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `memory`    | yes     | In-memory credential, tenant, task queue, event bus, session-friendly local development, and `cloud-wallet-kms/memory-backend`. |
| `redis`     | no      | Redis-backed issuance task queue and event publisher/subscriber. Requires Redis 7+ and RESP3 for event subscriptions.           |
| `mysql`     | no      | MySQL credential/tenant repositories, `sqlx/mysql`, and `cloud-wallet-kms/mysql`.                                               |
| `postgres`  | no      | PostgreSQL credential/tenant repositories, `sqlx/postgres`, and `cloud-wallet-kms/postgres`.                                    |
| `sqlite`    | no      | SQLite credential/tenant repositories, `sqlx/sqlite`, and `cloud-wallet-kms/sqlite`.                                            |
| `local-kms` | yes     | Local KMS provider for development and tests via `cloud-wallet-kms/local-kms`.                                                  |
| `aws-kms`   | no      | AWS KMS provider via `cloud-wallet-kms/aws-kms` and AWS SDK configuration loading.                                              |

## Runtime Configuration

`APP_BACKEND` selects the repository backend:

| `APP_BACKEND` | Required features                                          | External services                                                                      |
| ------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `memory`      | `memory` plus `local-kms` or `aws-kms`                     | None for `local-kms`; AWS credentials for `aws-kms`.                                   |
| `mysql`       | `mysql`; usually `redis`; plus `local-kms` or `aws-kms`    | MySQL database. Redis is recommended for distributed issuance workers.                 |
| `postgres`    | `postgres`; usually `redis`; plus `local-kms` or `aws-kms` | PostgreSQL database. Redis is recommended for distributed issuance workers.            |
| `sqlite`      | `sqlite`; plus `local-kms` or `aws-kms`                    | SQLite file path. Redis is optional and usually unnecessary for local single-node use. |

`APP_KMS__PROVIDER` selects key management:

| `APP_KMS__PROVIDER` | Required features | Requirements                                                                                               |
| ------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| `local`             | `local-kms`       | Development/test only. With SQL backends, DEKs are persisted through the selected SQL KMS storage backend. |
| `aws`               | `aws-kms`         | AWS credentials and region. `APP_KMS__AWS_REGION` can override region loading.                             |

If runtime configuration names a backend whose feature was not compiled, startup fails with a clear error.

## Supported Combinations

These combinations are intended to be supported and tested:

```bash
cargo check --no-default-features --features memory
cargo check --no-default-features --features mysql,redis,aws-kms
cargo check --no-default-features --features postgres,redis,aws-kms
cargo check --no-default-features --features sqlite,local-kms
cargo test --workspace --all-targets --all-features
```

Valid production examples include `aws-kms + mysql + redis`, `aws-kms + postgres + redis`, and `aws-kms + sqlite` for small single-node deployments. `local-kms` is intentionally suitable for development and CI only.

When both `local-kms` and `aws-kms` are compiled, `APP_KMS__PROVIDER` decides which provider is used at runtime. This keeps `--all-features` useful for CI while avoiding ambiguous startup behavior.

## Local Development

Default local run:

```bash
cargo run
```

SQLite with local KMS:

```bash
cargo run --no-default-features --features sqlite,local-kms
APP_BACKEND=sqlite
APP_DATABASE__URL=sqlite:./data/cloud_wallet.db
APP_KMS__PROVIDER=local
```

MySQL, Redis, and AWS KMS:

```bash
cargo run --no-default-features --features mysql,redis,aws-kms
APP_BACKEND=mysql
APP_DATABASE__URL=mysql://user:pass@localhost:3306/cloud_wallet
APP_REDIS__URI=redis://localhost:6379?protocol=resp3
APP_KMS__PROVIDER=aws
APP_KMS__AWS_REGION=us-east-1
```

## xtask Profiles

The `xtask` workspace member provides profile-based commands that automatically configure the correct Cargo features for each deployment environment:

| Profile       | Features                         | Use case                                       |
| ------------- | -------------------------------- | ---------------------------------------------- |
| `development` | `memory`, `local-kms`            | Local development, no external services needed |
| `staging`     | `postgres`, `redis`, `local-kms` | Pre-production testing with real databases     |
| `production`  | `postgres`, `redis`, `aws-kms`   | Production deployment with AWS KMS             |

```bash
# List available profiles
cargo xtask list

# Build and run with a profile
cargo xtask run development
cargo xtask run staging
cargo xtask run production

# Quick alias for development
cargo xtask dev

# Build, check, or test with a profile
cargo xtask build staging --release
cargo xtask check production
cargo xtask test development

# Print the Cargo features for a profile
cargo xtask features staging
```

Each profile passes `--no-default-features` and selects only the features listed above, ensuring the binary includes exactly the backends needed for that environment.
