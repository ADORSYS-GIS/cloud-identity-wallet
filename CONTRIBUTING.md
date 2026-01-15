# Contributing

Thanks for your interest in contributing to Cloud Identity Wallet! The project aims to implement a cloud-hosted, SSI/EUDI-aligned wallet with OIDC4VCI and OIDC4VP.

## Code of Conduct
Be respectful and inclusive. Harassment and abuse are not tolerated.

## Getting Started
1. Fork the repository and create a feature branch: `git checkout -b feat/short-description`.
2. Ensure you have the Rust toolchain installed via rustup (stable).
3. Run formatting and lints locally before pushing.

## Development workflow
- Prefer small, focused PRs.
- Include tests for new behavior; update docs when behavior changes.
- Keep commits concise and meaningful; reference issues in commit messages.
- Use conventional commit prefixes where possible (feat, fix, docs, chore, refactor, test).

## Rust idioms and project conventions
- Use `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`.
- Error handling: prefer `thiserror` for error types and `anyhow` for app-level errors.
- Avoid `unwrap()`/`expect()` in production code; bubble errors with context (`anyhow::Context`).
- Prefer explicit types and `From/Into` for conversions; derive `Debug` for structs/enums.
- Use `tracing` for structured logs; avoid `println!`.
- Manage secrets using typed wrappers that implement `Zeroize` when applicable.
- Follow `tokio` async patterns; avoid blocking in async contexts.

## Testing
- Unit tests close to the code under test.
- Integration tests under `tests/` exercising public interfaces.
- Add protocol flow tests for OIDC4VCI and OIDC4VP as they are implemented.

## Documentation
- Update `README.md` and `docs/architecture.md` when adding or changing components or flows.
- Include sequence or component diagrams when it helps understanding. Use the existing images in `docs/Arch-images/` or add new ones there.

## Pull requests
1. Ensure CI is green (build, test, clippy, fmt).
2. Provide a clear description, rationale, and screenshots/sequence diagrams if relevant.
3. Request a review from maintainers.

## License
By contributing, you agree that your contributions will be licensed under the repository's license.
