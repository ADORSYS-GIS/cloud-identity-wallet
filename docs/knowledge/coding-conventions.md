# Coding Conventions — cloud-identity-wallet

## Naming Standards

| Element                         | Convention                                                         | Example                         |
|---------------------------------|--------------------------------------------------------------------|---------------------------------|
| Variables, functions, methods, modules | `snake_case`                                                 | `get_credential`, `user_id`     |
| Types, traits, enums            | `PascalCase`                                                       | `CredentialOffer`, `ValidationError` |
| Constants and statics           | `SCREAMING_SNAKE_CASE`                                             | `MAX_CREDENTIALS`, `DEFAULT_TIMEOUT` |
| Lifetime parameters             | Short lowercase (`'a`, `'b`); descriptive for clarity (`'conn`, `'ctx`) |                                 |
| Crate names                     | `kebab-case` in Cargo.toml, `snake_case` in code                   | `cloud-identity-wallet`         |
| Files                           | `snake_case.rs`                                                    | `credential_offer.rs`           |
| Type conversions                | `from_*`, `to_*`, `into_*`, `as_*`                                 | `from_bytes`, `to_string`       |

## File Organization

```text
cloud-identity-wallet/
├── crates/
│   ├── cloud-identity-wallet/    # Main application (Axum-based API)
│   └── cloud-wallet-events/      # Event handling for credential lifecycle
├── docs/
│   └── knowledge/                # Project knowledge documentation
├── tests/                        # Integration tests
└── Cargo.toml                    # Workspace root
```

- Keep `lib.rs`/`main.rs` thin — re-export public API and delegate to submodules
- Use `pub(crate)` for internal visibility; minimize the public surface area
- Group related types, traits, and functions into modules by domain concept
- Place integration tests in `tests/` directory; unit tests in `#[cfg(test)]` modules within source files

## Code Formatting

- **Formatter**: `rustfmt`
- **Config file**: `rustfmt.toml` or via `Cargo.toml`
- **Edition**: Rust 2024
- **Linting**: Clippy, rustdoc (broken intra-doc links denied)

## Import Ordering

1. Standard library (`use std::...`)
2. External crates (`use anyhow::...`, `use axum::...`)
3. Internal crates (`use crate::...`)
4. Current module items (`use super::...`, `use self::...`)

## Ownership and Borrowing

- Default to borrowing (`&T`); only take ownership when the function needs to consume or store the value
- Prefer `&str` over `&String`, `&[T]` over `&Vec<T>` in function parameters
- Use `Clone` explicitly rather than implicit copies; annotate why a clone is necessary if non-obvious
- Return owned types from constructors and factory functions
- Minimize lifetime annotations — let the compiler infer where possible
- Use `Cow<'_, str>` when a function may or may not need to allocate

## Error Handling

- Use `Result<T, E>` for all fallible operations; never panic in library code
- Define a crate-level error enum using `thiserror` for libraries or `anyhow` for applications
- Use the `?` operator for error propagation; add context with `.context()` (anyhow) or `.map_err()`
- Reserve `unwrap()` and `expect()` for cases with compile-time or logical guarantees; always add a message to `expect()`
- Use `panic!` only for programming errors (invariant violations), never for expected failures

### Error Types

| Error Type                    | Description                        |
|-------------------------------|------------------------------------|
| `ValidationError::SchemaMismatch` | Schema validation failures      |
| `CredentialError`             | Credential lifecycle state errors  |

### Error Messages

- Include stable schema identifiers
- Provide actionable information
- Document provenance where relevant

## Comment Standards

- **Public APIs**: Doc comments (`///` or `//!`) explaining purpose, parameters, return values, and thrown errors
- **Complex logic**: Inline comments explaining *why*, not *what*
- **TODO format**: `TODO(username): description`
- **Safety comments**: Use `// SAFETY:` comments for `unsafe` blocks documenting safety invariants

## Feature Gates

- Heavy dependencies should be feature-gated
- Default build should be lightweight
- Document feature requirements in code

Example:

```toml
[features]
default = []
schema-validation = ["jsonschema"]
```

## Namespace Handling

- ISO mdoc claims are namespace-qualified (e.g., `org.iso.18013-5.1`)
- Claims extraction must respect namespace boundaries
- Different credential formats have different claims structures

## Commit Message Format

Use Conventional Commits: `type(scope): description`

- **Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- **Scope**: Optional but encouraged (e.g., `feat(auth): add OAuth2 flow`)
- **Subject line**: Imperative mood, lowercase, no period, max 72 characters
- **Body**: Explain *why* the change was made, not *what* changed

## Code Review Checklist

When reviewing PRs, verify:

- [ ] **Spec Compliance**: Does implementation match OpenID4VCI/OpenID4VP specs?
- [ ] **Format Handling**: Are credential format differences properly handled?
- [ ] **Feature Gates**: Are heavy dependencies properly gated?
- [ ] **Namespace Awareness**: Are mdoc claims namespace-qualified?
- [ ] **Error Quality**: Are error messages informative and stable?
- [ ] **Rust Edition**: Is code compatible with Rust 2024 edition?
- [ ] **CI Alignment**: Does code match CI toolchain expectations?
- [ ] **Scope**: Is the change within project scope boundaries?
- [ ] Tests included for new functionality
- [ ] No hardcoded secrets or credentials
- [ ] Error handling is appropriate
- [ ] Documentation updated if needed
