# Cloud Wallet Cryptographic Library

[![CI](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/cloud-identity-wallet/actions/workflows/ci.yml)
[![GitHub](https://img.shields.io/badge/repo-cloud--wallet--crypto-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![Rust](https://img.shields.io/badge/msrv-1.92-blue)](https://github.com/ADORSYS-GIS/cloud-identity-wallet)
[![license](https://shields.io/badge/license-MIT%2FApache--2.0-blue)](#license)

A high-level cryptographic library providing clean and easy-to-use APIs for common cryptographic operations. Built on [AWS-LC](https://github.com/aws/aws-lc) via [aws-lc-rs](https://github.com/aws/aws-lc-rs), offering FIPS-validated cryptography.

It is aimed at use with the [cloud-identity-wallet](https://github.com/ADORSYS-GIS/cloud-identity-wallet) project, but can be used in any other project as well.

## Feature Flags

**`jwk`**

Enables support for JSON Web Keys (JWK), including serialization and deserialization of cryptographic keys.

```toml
[dependencies]
cloud-wallet-crypto = { version = "0.1", features = ["jwk"] }
```

**`fips`**

Enables support for FIPS-validated cryptography (backed by AWS-LC).

```toml
[dependencies]
cloud-wallet-crypto = { version = "0.1", features = ["fips"] }
```

When building with the `fips` feature enabled, **`cmake`**, **`go`** and potentially **`bindgen`** are required.
See [Building](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-rs#build) for more details.

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
cloud-wallet-crypto = "0.1"
```

A C compiler (e.g. **`clang`** or **`gcc`** ) is required for building the library. See [Building](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-rs#build) for more information.

### Basic Example

```rust
use cloud_wallet_crypto::{
    aead::{Algorithm, Key},
    ecdsa::{self, Curve},
    digest::HashAlg,
    rand,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Encrypt data with AES-256-GCM
    let key = Key::generate(Algorithm::AesGcm256)?;
    let mut nonce = [0u8; 12];
    rand::fill_bytes(&mut nonce)?;
    let mut data = *b"Secret message";
    let tag = key.encrypt(&nonce, b"metadata", &mut data)?;

    // Sign with ECDSA
    let keypair = ecdsa::KeyPair::generate(Curve::P256)?;
    let signature = keypair.sign_sha256(b"Important document")?;
    keypair.public_key().verify_sha256(b"Important document", &signature)?;

    // Hash data with SHA-256
    let digest = HashAlg::Sha256.hash(b"hello world");
    Ok(())
}
```

## Usage Examples

### AEAD Encryption

```rust
use cloud_wallet_crypto::aead::{Algorithm, Key};
use cloud_wallet_crypto::rand;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a key
    let key = Key::generate(Algorithm::AesGcm256)?;

    // Prepare data
    let plaintext = b"Secret message";
    let mut nonce = [0u8; 12];
    rand::fill_bytes(&mut nonce)?;
    let aad = b"additional authenticated data";

    // Encrypt in-place
    let mut buffer = plaintext.to_vec();
    key.encrypt_append_tag(&nonce, aad, &mut buffer)?;
    // buffer now contains ciphertext + authentication tag

    // Decrypt
    let plaintext = key.decrypt(&nonce, aad, &mut buffer)?;
    Ok(())
}
```

> **⚠️ Warning**: Never reuse a nonce with the same key. Each encryption must use a unique nonce.

### Digital Signatures

#### ECDSA (Recommended for most use cases)

```rust
use cloud_wallet_crypto::ecdsa::{KeyPair, Curve};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate P-256 key pair
    let keypair = KeyPair::generate(Curve::P256)?;

    // Sign with SHA-256 (returns 64-byte fixed signature)
    let message = b"Document to sign";
    let signature = keypair.sign_sha256(message)?;

    // Verify
    keypair.public_key().verify_sha256(message, &signature)?;

    // Serialize keys
    let pkcs8_der = keypair.to_pkcs8_der();
    let spki_der = keypair.public_key().to_spki_der();
    Ok(())
}
```

#### Ed25519 (Fastest signatures)

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cloud_wallet_crypto::ed25519::KeyPair;

    let keypair = KeyPair::generate()?;

    // Sign (deterministic, no nonce needed)
    let signature = keypair.sign(b"message");

    // Verify
    keypair.public_key().verify(b"message", &signature)?;
    Ok(())
}
```

#### RSA (Widest compatibility)

```rust
use cloud_wallet_crypto::rsa::{KeyPair, RsaKeySize};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate 4096-bit key
    let keypair = KeyPair::generate(RsaKeySize::Rsa4096)?;

    // Sign with PKCS#1 v1.5 padding
    let mut signature = vec![0u8; 512]; // RSA-4096 = 512 bytes
    let sig = keypair.sign_pkcs1_sha256(b"message", &mut signature)?;

    // Verify
    keypair.public_key().verify_pkcs1_sha256(b"message", sig)?;
    Ok(())
}
```

### Cryptographic Hashing

```rust
use cloud_wallet_crypto::digest::{HashAlg, Hasher};

// One-shot hashing
let digest = HashAlg::Sha256.hash(b"data to hash");

// Streaming API for large data
let mut hasher = Hasher::new(HashAlg::Sha256);
hasher.update(b"part 1");
hasher.update(b"part 2");
let digest = hasher.finalize();

// Verify digest
assert_eq!(digest.as_ref().len(), 32); // SHA-256 = 32 bytes
```

### JSON Web Keys (JWK)

> **Note**: JWK support requires the `jwk` feature flag.

```rust
# #[cfg(not(feature = "jwk"))]
# fn main() {}
# #[cfg(feature = "jwk")]
use cloud_wallet_crypto::{
    ecdsa::{KeyPair, Curve},
    jwk::{Jwk, Parameters, Algorithm, Signing},
};

# #[cfg(feature = "jwk")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key and convert to JWK
    let keypair = KeyPair::generate(Curve::P256)?;
    let mut jwk = Jwk::try_from(&keypair)?;

    // Add metadata
    jwk.prm = Parameters {
        kid: Some("signing-key".to_string()),
        alg: Some(Algorithm::Signing(Signing::Es256)),
        ..Default::default()
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&jwk)?;

    // Parse from JSON
    let parsed: Jwk = serde_json::from_str(&json)?;

    // Convert back to verifying key
    let verifying_key = cloud_wallet_crypto::ecdsa::VerifyingKey::try_from(&parsed)?;
    Ok(())
}
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Acknowledgments

This project is built on [AWS-LC](https://github.com/aws/aws-lc), Amazon's cryptographic
library derived from Google's BoringSSL, providing FIPS 140-3 validated cryptography.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
