pub mod credential;
pub mod repository;
pub mod service;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mongodb")]
pub mod mongodb;

// Convenient re-exports
pub use credential::{Credential, CredentialFormat, CredentialMetadata, CredentialStatus};
pub use repository::{CredentialFilter, CredentialRepository, StoreError};
pub use service::CredentialService;
