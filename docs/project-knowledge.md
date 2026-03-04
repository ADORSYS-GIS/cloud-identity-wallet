# Project Knowledge Summary for PR Reviews

This document provides essential context for reviewing PRs in the Cloud Identity Wallet project.

## Project Overview

**Cloud Identity Wallet** is a cloud-hosted, multi-tenant verifiable credential wallet for SSI- and eIDAS-aligned ecosystems.

- **Repository**: `ADORSYS-GIS/cloud-identity-wallet`
- **License**: MIT OR Apache-2.0
- **Status**: Active development, core building blocks being implemented incrementally

### Core Capabilities

- **Multi-Tenant Architecture**: Host multiple organizations with strong data isolation
- **Modular Design**: Pluggable credential formats, storage backends, key management
- **Webhook & Audit Logging**: Track credential events for observability/compliance

## Technical Stack

### Rust Configuration

- **Edition**: Rust 2024
- **Workspace**: Single workspace with multiple crates
- **Resolver**: Version 2
- **Linting**: Clippy, rustdoc (broken intra-doc links denied)

### Key Crates

| Crate | Purpose |
|-------|---------|
| `cloud-identity-wallet` | Main application (Axum-based API) |
| `cloud-wallet-events` | Event handling for credential lifecycle |

### Dependencies of Note

- `axum` - Web framework
- `tokio` - Async runtime
- `serde` - Serialization
- `tracing` - Logging/observability
- `jsonschema` - JSON Schema validation (feature-gated)

## OpenID4VC Standards

### OpenID4VCI (Credential Issuance)

**Spec**: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

**Supported Flows**:
- Authorization Code Flow
- Pre-Authorized Code Flow

**Key Concepts**:
- Credential Offer: Can contain multiple credentials; UI should allow user selection
- Nonce Endpoint: Nonce requested at dedicated endpoint, not at credential-offer dereference time
- Access Token: UI obtains/handles token (mediated through wallet backend)

### OpenID4VP (Verifiable Presentations)

**Spec**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

**Key Concepts**:
- Presentation Request handling
- User selects credentials/data to present
- Generate presentation/proof and return to verifier

## Credential Formats

### Supported Formats

| Format ID | Description |
|-----------|-------------|
| `vc+sd-jwt` | SD-JWT based verifiable credentials (selective disclosure) |
| `mso_mdoc` | ISO 18013-5 mobile documents (mDL/mdoc) |
| `jwt_vc_json` | JWT-based verifiable credentials (JSON claims) |

### Format-Specific Validation

#### mso_mdoc (ISO mdoc)
- **Namespace-aware claims**: Claims extracted per namespace (e.g., `org.iso.18013-5.1`)
- **Schema validation**: Uses JSON Schema with feature gate `schema-validation`
- **Claims structure**: Different from JWT-based formats

#### vc+sd-jwt
- Selective disclosure capabilities
- Holder binding support

## Architecture Patterns

### Split Wallet Architecture

- **UI Client**: User interaction, consent, credential selection
- **Remote Wallet Backend API**: Protocol handling, storage, key management, proofs

### Component Model

**In Scope**:
- Wallet Backend API
- OpenID4VCI Adapter (issuance)
- OID4VP Adapter (presentation)
- Credential Lifecycle (import, store, list, update status, delete)
- Presentation & Proof Engine
- Encrypted Storage
- Key Management

**Out of Scope**:
- External Issuers
- External Verifiers
- Revocation/Status Lists hosting
- Trust establishment frameworks

## Validation Patterns

### JSON Schema Validation

- Feature-gated under `schema-validation` feature
- Uses `jsonschema` crate as optional dependency
- Avoids heavy native dependencies in default builds

### Error Types

- `ValidationError::SchemaMismatch` - Schema validation failures
- `CredentialError` - Credential lifecycle state errors

### Schema Identifiers

- Use stable identifiers in validation errors
- Schema provenance should be documented
- Guardrails for schema application

## Code Style Guidelines

### Feature Gates

- Heavy dependencies should be feature-gated
- Default build should be lightweight
- Document feature requirements in code

### Namespace Handling

- ISO mdoc claims are namespace-qualified
- Claims extraction must respect namespace boundaries

### Error Messages

- Include stable schema identifiers
- Provide actionable information
- Document provenance where relevant

## EU/EUDI Context

### Relevant Standards

- **EU Digital Identity Wallet RFCs**: https://github.com/EWC-consortium/eudi-wallet-rfcs
- **EU Business Wallets**: https://digital-strategy.ec.europa.eu/en/library/proposal-regulation-establishment-european-business-wallets

### Compliance Considerations

- eIDAS alignment
- Privacy-preserving selective disclosure
- Encrypted storage requirements
- Secure key management

## Review Checklist

When reviewing PRs, verify:

1. **Spec Compliance**: Does implementation match OpenID4VCI/OpenID4VP specs?
2. **Format Handling**: Are credential format differences properly handled?
3. **Feature Gates**: Are heavy dependencies properly gated?
4. **Namespace Awareness**: Are mdoc claims namespace-qualified?
5. **Error Quality**: Are error messages informative and stable?
6. **Rust Edition**: Is code compatible with Rust 2024 edition?
7. **CI Alignment**: Does code match CI toolchain expectations?
8. **Scope**: Is the change within project scope boundaries?
