# Cloud Identity Wallet

[![CI](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml)
[![dependencies](https://deps.rs/repo/github/ADORSYS-GIS/cloud-identity-wallet/status.svg)](https://deps.rs/repo/github/ADORSYS-GIS/cloud-identity-wallet)
[![license](https://shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

**Cloud Identity Wallet** is a cloud-hosted, multi-tenant verifiable credential wallet designed for **issuers, holders, and verifiers** operating in SSI- and eIDAS-aligned ecosystems.

It implements:

- [OpenID for Verifiable Credential Issuance (OpenID4VCI)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) for credential issuance
- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) for credential presentation

The project is designed to support a wide range of credential formats while enabling privacy-preserving disclosure and interoperability across EUDI-compatible systems.

> ⚠️ **Project status**  
> This repository is under active development. Core building blocks are being implemented incrementally and APIs may change.

## Key Capabilities

This project focuses on server-side wallet capabilities.

### Core Wallet Features

- **Multi-Tenant Architecture**  
  Host multiple organizations and tenants in a single instance with strong data isolation.

- **Modular Design**  
  Pluggable components for credential formats, storage backends, and key management systems.

- **Webhook & Audit Logging**  
  Track credential issuance and presentation events for observability and compliance.

### Standards & Interoperability

- OpenID4VCI (credential issuance)
- OpenID4VP (verifiable presentations)
- Support for standardized credential formats:
  - SD-JWT
  - ISO 18013-5 (mDL / mdoc)
  - W3C Verifiable Credentials Data Model

### Privacy & Security

- Privacy-preserving selective disclosure
- Encrypted storage
- Secure key management abstractions
- Designed for compliance-driven environments (eIDAS / EUDI)

## Architecture Overview

![Architecture overview](./assets/communication_flow.png)

A detailed breakdown of components, trust boundaries, and protocol flows is available in **[ARCHITECTURE.md](./docs/architecture.md)**.

## Build and Test

### Prerequisites

- [Rust & Cargo](https://www.rust-lang.org/tools/install) (latest stable version)
- An optional alternative linker for faster builds (see [linking guide](./docs/linking.md))

### Setup

```bash
git clone https://github.com/ADORSYS-GIS/cloud-identity-wallet.git
cd cloud-identity-wallet
```

### Running the application

```bash
cargo run
```

### Testing

You can run the full test suite with:

```bash
cargo test --workspace --all-targets --all-features
```

Or optionally with [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/) for faster test execution:

```bash
cargo nextest run --workspace --all-targets --all-features
```

## Contributing

Contributions are welcome and encouraged. Before contributing, please review the [architecture documentation](./docs/architecture.md), which provides an overview of our architectural design. Also refer to the [contributing guide](./CONTRIBUTING.md) for more details.  
Discussions around standards compliance, interoperability, and extensibility are especially welcome.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
