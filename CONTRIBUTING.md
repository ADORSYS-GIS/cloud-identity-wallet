# Contributing

Thanks for your interest in contributing to Cloud Identity Wallet! The project aims to implement a cloud-hosted, SSI/EUDI-aligned wallet with OpenID4VCI and OpenID4VP.

## Code of Conduct

Be respectful and inclusive. Harassment and abuse are not tolerated.

## Getting Started

1. Fork the repository and create a topic branch: `git checkout -b <type>/<short-description>` (e.g., `feat/`, `fix/`, `docs/`, `chore/`, `refactor/`, `test`).
2. Ensure you have the Rust toolchain installed via rustup (stable).
3. Run formatting and lints locally before pushing.

Feature requests: please open an issue to discuss scope/design before implementation.

## Development workflow

- Prefer small, focused PRs.
- Include tests for new behavior; update docs when behavior changes.
- Keep commits concise and meaningful; reference issues in commit messages.
- Use conventional commit prefixes where possible (feat, fix, docs, chore, refactor, test).

## Rust idioms and project conventions

- Use `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`.
- Error handling: use a consistent, robust strategy; define clear error types where appropriate and propagate errors with helpful context.
- Avoid `unwrap()`/`expect()` as much as possible.
- Prefer explicit types and `From/Into` for conversions; derive `Debug` for structs/enums.
- Use `tracing` for structured logs; avoid `println!`.
- Manage secrets using typed wrappers that implement `Zeroize` when applicable.
- Follow `tokio` async patterns; avoid blocking in async contexts.

## Testing

- Unit tests close to the code under test.
- Integration tests under `tests/` exercising public interfaces.
- Add protocol flow tests for OpenID4VCI and OpenID4VP as they are implemented.

## Documentation

- Update `README.md` and `docs/architecture.md` when adding or changing components or flows.
- Include sequence or component diagrams when it helps understanding. Use the existing images in `docs/assets/` or add new ones there.

## Pull requests

1. Ensure CI is green (build, test, clippy, fmt).
2. Provide a clear description, rationale, and screenshots/sequence diagrams if relevant.
3. Request a review from maintainers.

## License

By contributing, you agree that your contributions will be licensed under the repository's license.
