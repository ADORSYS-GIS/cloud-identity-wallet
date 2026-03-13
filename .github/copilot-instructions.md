# cloud-identity-wallet

## Reference Documentation

**ALWAYS read these files for implementation references and decision guides before making changes:**

| File | Purpose |
|------|---------|
| `docs/knowledge/architecture.md` | System architecture, components, protocol flows, key management |
| `docs/knowledge/coding-conventions.md` | Rust naming, ownership patterns, error handling, feature gates |
| `docs/knowledge/development-setup.md` | Prerequisites, linker setup, build/test commands |
| `docs/knowledge/api-reference.md` | OpenID4VCI/OpenID4VP endpoints, credential formats, error codes |
| `docs/project-knowledge.md` | PR review checklist, EU/EUDI context |

## Tech Stack

- **Languages:** rust
- **Frameworks:** axum
- **Package Managers:** cargo
- **Test Frameworks:** cargotest

## Repository Structure

```text
monorepo
```

## Core Principles

- Write clean, readable code. Favor clarity over cleverness.
- Every change must leave the codebase better than you found it.
- Security is non-negotiable. Follow OWASP guidelines for all user-facing code.
- Never commit secrets, API keys, tokens, or credentials. Use environment variables and secret managers.
- All public APIs must have input validation and proper error handling.
- Prefer composition over inheritance. Favor small, focused functions.

## Git Conventions

### Commits

- Use Conventional Commits: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`
- Scope is optional but encouraged (e.g., `feat(auth): add OAuth2 flow`)
- Subject line: imperative mood, lowercase, no period, max 72 characters
- Body: explain *why* the change was made, not *what* changed (the diff shows that)

### Branches

- Feature: `feat/short-description` or `feat/TICKET-123-short-description`
- Bugfix: `fix/short-description`
- Hotfix: `hotfix/short-description`
- Release: `release/vX.Y.Z`

### Pull Requests

- PRs must have a clear description of changes and motivation
- All CI checks must pass before merge
- Require at least one approving review
- Keep PRs small and focused; split large changes into stacked PRs
- Link related issues using `Closes #123` or `Fixes #123`

## Code Review Standards

- Review for correctness, security, performance, and readability in that order
- Check for proper error handling and edge cases
- Verify test coverage for new and changed code
- Flag any hardcoded values that should be configurable
- Ensure naming is clear and consistent with the codebase
- Look for potential race conditions in concurrent code

## Error Handling Philosophy

- Fail fast and fail loudly in development; fail gracefully in production
- Use typed/structured errors, not raw strings
- Always log errors with sufficient context for debugging (timestamp, request ID, stack trace)
- Never swallow exceptions silently
- Distinguish between recoverable and unrecoverable errors
- Return meaningful error messages to API consumers (without leaking internals)

## Documentation Expectations

- Public functions and APIs must have doc comments explaining purpose, parameters, return values, and thrown errors
- Complex business logic must have inline comments explaining *why*, not *what*
- Keep README up to date when adding features, changing setup steps, or modifying architecture
- Document breaking changes prominently in changelogs
- Architecture decisions should be recorded in ADRs (Architecture Decision Records) when significant

## Rust Conventions

### Naming

- Variables, functions, methods, modules: `snake_case`
- Types, traits, enums: `PascalCase`
- Constants and statics: `SCREAMING_SNAKE_CASE`
- Lifetime parameters: short lowercase (`'a`, `'b`); use descriptive names for clarity (`'conn`, `'ctx`)
- Crate names: `kebab-case` in Cargo.toml, `snake_case` in code (auto-converted)
- Files: `snake_case.rs`; module directories with `mod.rs` or `module_name.rs` + `module_name/`
- Type conversions: `from_*`, `to_*`, `into_*`, `as_*` following std conventions

### Ownership and Borrowing

- Default to borrowing (`&T`); only take ownership when the function needs to consume or store the value
- Prefer `&str` over `&String`, `&[T]` over `&Vec<T>` in function parameters
- Use `Clone` explicitly rather than implicit copies; annotate why a clone is necessary if non-obvious
- Return owned types from constructors and factory functions
- Minimize lifetime annotations — let the compiler infer where possible
- Use `Cow<'_, str>` when a function may or may not need to allocate

### Error Handling

- Use `Result<T, E>` for all fallible operations; never panic in library code
- Define a crate-level error enum using `thiserror` for libraries or `anyhow` for applications
- Use the `?` operator for error propagation; add context with `.context()` (anyhow) or `.map_err()`
- Reserve `unwrap()` and `expect()` for cases with compile-time or logical guarantees; always add a message to `expect()`
- Use `panic!` only for programming errors (invariant violations), never for expected failures

### Module Organization

- Keep `lib.rs`/`main.rs` thin — re-export public API and delegate to submodules
- Use `pub(crate)` for internal visibility; minimize the public surface area
- Group related types, traits, and functions into modules by domain concept
- Place integration tests in `tests/` directory; unit tests in `#[cfg(test)]` modules within source files

### Patterns and Idioms

- Use `enum` with variants for state machines and discriminated unions
- Implement `Display` and `Debug` for all public types
- Use `impl Into<T>` / `impl AsRef<T>` for flexible function parameters
- Prefer iterators and combinators (`.map()`, `.filter()`, `.collect()`) over manual loops
- Use `derive` macros for `Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize` as appropriate
- Prefer `Option` methods (`.map()`, `.and_then()`, `.unwrap_or_default()`) over `match` for simple cases
- Use newtype pattern (`struct UserId(u64)`) for type safety on primitive wrappers

### Common Pitfalls

- Avoid `String::from` / `.to_string()` in hot loops; reuse buffers
- Beware of holding `MutexGuard` across `.await` points — use `tokio::sync::Mutex` in async code
- Do not use `Rc`/`Arc` unless shared ownership is truly needed
- Avoid `unsafe` unless absolutely necessary; document safety invariants in `// SAFETY:` comments
- Run `cargo clippy` in CI and fix all warnings; do not suppress without justification
- Use `#[must_use]` on functions whose return values should not be ignored

## Axum Conventions

### Project Structure

- Entry point: `src/main.rs` with `tokio::main` async runtime and `axum::Router`
- Handlers: `src/handlers/{resource}.rs` with async handler functions
- Services: `src/services/{resource}.rs` for business logic
- Models: `src/models/` for domain types and DTOs (with `serde::Serialize`/`Deserialize`)
- State: `src/state.rs` for shared application state (`AppState`)
- Error: `src/error.rs` for custom error types implementing `IntoResponse`
- Routes: `src/routes.rs` composing the router from sub-routers

### Route and Handler Patterns

- Build routers: `Router::new().route("/users", get(list_users).post(create_user))`
- Nest routers: `Router::new().nest("/api/v1", api_routes())`
- Handlers are async functions with extractors as parameters
- Extractors: `Path(id): Path<Uuid>`, `Json(body): Json<CreateUser>`, `Query(params): Query<ListParams>`
- Return `impl IntoResponse` or specific types: `Json<T>`, `(StatusCode, Json<T>)`

### State and Dependency Injection

- Define `AppState` struct with `Arc`: `#[derive(Clone)] struct AppState { db: PgPool, config: Arc<Config> }`
- Pass state to router: `Router::new().with_state(state)` and extract with `State(state): State<AppState>`
- Use `FromRef` derive for substates: extractors can pull specific fields from `AppState`
- Prefer `Extension<T>` only for middleware-injected per-request values

### Extractors

- Axum extracts handler parameters in order; the last extractor can consume the request body
- Body extractors (`Json`, `Form`, `Bytes`) must be the last parameter
- Custom extractors: implement `FromRequestParts<S>` (non-body) or `FromRequest<S>` (body)
- Rejection handling: implement `From<JsonRejection>` on your error type for custom error responses
- Use `Option<T>` for optional extractors; `Result<T, E>` to handle extraction failures manually

### Error Handling

- Define `AppError` enum implementing `IntoResponse` for all handler errors
- Use `thiserror` for error definitions; map to `(StatusCode, Json<ErrorBody>)` in `IntoResponse`
- Use the `?` operator in handlers by returning `Result<impl IntoResponse, AppError>`
- Log errors in the `IntoResponse` implementation; return sanitized messages to clients

### Middleware

- Use `tower` middleware: `ServiceBuilder::new().layer(TraceLayer::new(...)).layer(CorsLayer::new(...))`
- Apply per-route: `Router::new().route("/", get(handler)).layer(middleware)`
- Use `axum::middleware::from_fn` for custom async middleware functions
- Use `tower-http` crate for common middleware: CORS, compression, request tracing, timeout

### Anti-Patterns to Avoid

- Do not use `unwrap()` in handlers — return `Result` with a proper error type
- Do not hold `MutexGuard` across `.await` points — use `tokio::sync::Mutex` if needed
- Do not block the async runtime — use `tokio::task::spawn_blocking` for CPU-intensive work
- Do not forget to add `#[derive(Deserialize)]` on request types and `#[derive(Serialize)]` on response types
- Do not create a new database pool per request — share via `AppState`

## Testing Conventions

**Test Frameworks:** cargotest

### Test File Naming and Location

- Test files live alongside source files or in a parallel `tests/`/`__tests__` directory — follow the established project convention
- Name test files to match the module they test: `user-service.test.ts`, `test_user_service.py`, `UserServiceTest.java`
- Group integration tests separately from unit tests (e.g., `tests/integration/`, `tests/unit/`)

### Test Structure (AAA Pattern)

- Every test follows **Arrange / Act / Assert**:
  - **Arrange**: Set up test data, mocks, and preconditions
  - **Act**: Execute the single operation under test
  - **Assert**: Verify the expected outcome
- Separate the three sections with blank lines for readability
- Each test should have exactly one reason to fail — test one behavior per test function

### What to Test

- All public API methods and functions
- Business logic and domain rules
- Edge cases: empty inputs, boundary values, null/undefined, max/min values
- Error paths: invalid input, missing data, network failures, permission denied
- State transitions and side effects

### What NOT to Test

- Framework internals or third-party library behavior
- Private methods directly (test through the public interface)
- Trivial getters/setters with no logic
- Auto-generated code (ORM models, protobuf stubs)
- Implementation details that may change without affecting behavior

### Mocking Philosophy

- Mock external dependencies (HTTP clients, databases, file system, third-party APIs)
- Do NOT mock the unit under test or its direct collaborators (prefer real objects)
- Use dependency injection to make mocking straightforward
- Prefer fakes/stubs over complex mock frameworks when possible
- Assert on behavior (was the method called with correct args?) not implementation
- Reset mocks between tests to prevent state leakage

### Coverage Expectations

- Aim for 80%+ line coverage on business logic and domain code
- 100% coverage on critical paths (authentication, authorization, payment, data validation)
- Do not chase 100% coverage everywhere — diminishing returns on glue code and configuration
- Coverage gates in CI should block PRs that reduce coverage on changed files

### Integration vs Unit Test Boundaries

- **Unit tests**: fast, isolated, no I/O, no network, no database — run in milliseconds
- **Integration tests**: test real interactions between components (API routes, database queries, message queues)
- Integration tests use dedicated test databases/containers, not production-like data
- Run unit tests on every commit; run integration tests in CI pipeline
- Use test containers (Testcontainers, Docker Compose) for integration test infrastructure

### Test Quality

- Tests must be deterministic — no flaky tests; fix or quarantine immediately
- Tests must be independent — no reliance on execution order or shared mutable state
- Use descriptive test names that read as specifications: `should return 404 when user not found`
- Use test data builders or factories to reduce boilerplate setup
- Clean up test resources in teardown/afterEach hooks
