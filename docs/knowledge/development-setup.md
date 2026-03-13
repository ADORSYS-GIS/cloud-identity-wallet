# Development Setup — cloud-identity-wallet

## Prerequisites

| Tool     | Minimum Version | Installation                                  |
|---------|-----------------|-----------------------------------------------|
| Rust    | 2024 Edition    | [rustup](https://rustup.rs/)                  |
| Cargo   | Via Rust        | Included with Rust                            |
| Git     | 2.40+           | [git-scm.com](https://git-scm.com)            |
| Clippy  | Via Rust        | `rustup component add clippy`                 |
| rustfmt | Via Rust        | `rustup component add rustfmt`                |

## Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/ADORSYS-GIS/cloud-identity-wallet.git
cd cloud-identity-wallet
```

### 2. Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env with required values
```

## Link Time Optimizations

To reduce build times, especially during development, the use of faster alternative linkers is recommended.

> These optimizations are recommended but not strictly required. If the required linker is not available, Cargo will fall back to the system default.

### Platform Support

| Platform              | Status       | Notes                                        |
|-----------------------|--------------|----------------------------------------------|
| Linux                 | ✅ Supported | Uses `mold` for significantly faster linking |
| macOS (Apple Silicon) | ✅ Supported | Uses Apple's default `ld_prime` linker       |
| macOS (Intel)         | ✅ Supported | Uses LLVM's `lld` for faster linking         |
| Windows               | ❌ Unsupported | Not currently supported                      |

### Linux Setup

Install [`mold`](https://github.com/rui314/mold), a high-performance drop-in replacement for `GNU ld`:

```bash
sudo apt update
sudo apt install mold clang
```

Cargo configuration (`.cargo/config.toml`):

```toml
[target.'cfg(target_os = "linux")']
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

### macOS Setup

**Apple Silicon**: Uses `ld_prime` (already fast, no additional setup needed).

**Intel-based macOS**: Install LLVM's `lld`:

```bash
xcode-select --install  # Install Xcode Command Line Tools
brew install lld        # Install LLVM linker
```

Cargo configuration (optional):

```toml
[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

### Verification

```bash
mold --version  # Linux
lld --version   # macOS
```

To confirm `mold` is being used, inspect the `.comment` section of a compiled executable:

```bash
readelf -p .comment <executable-file>
```

## Running Locally

```bash
cargo run
```

## Running Tests

### Unit Tests

```bash
cargo test
```

### Integration Tests

```bash
cargo test --test '*'
```

### All Tests with Coverage

```bash
cargo tarpaulin
```

## Linting and Formatting

```bash
cargo fmt --check    # Check formatting
cargo fmt            # Apply formatting
cargo clippy         # Run linter
cargo clippy --fix   # Auto-fix lint issues
```

## Building for Production

```bash
cargo build --release
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Broken intra-doc links | Run `cargo doc` and fix reported link errors |
| Clippy warnings | Run `cargo clippy --fix` or fix manually |
| Slow builds on Linux | Ensure `mold` is installed and configured |
| Feature-gated dependency missing | Enable the required feature, e.g., `cargo build --features schema-validation` |
