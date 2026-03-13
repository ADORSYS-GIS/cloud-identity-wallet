pub mod config;
pub mod errors;
pub mod format;
pub mod models;
pub mod repository;
pub mod schema;

#[cfg(feature = "encryption")]
mod encryption;

#[cfg(feature = "encryption")]
pub mod encrypted_repository;

#[cfg(feature = "postgres")]
pub mod postgres;

// Re-export key types for convenience
pub use config::PostgresConfig;
pub use errors::StoreError;
pub use repository::{CredentialFilter, CredentialRepository};

#[cfg(feature = "encryption")]
pub use encryption::{Kek, StoredCredential, decrypt_credential, encrypt_credential};

#[cfg(feature = "encryption")]
pub use encrypted_repository::EncryptingRepository;

#[cfg(feature = "postgres")]
pub use postgres::PostgresCredentialRepository;
