use thiserror::Error;

/// Top level domain error type.
#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),

    #[error("Credential error: {0}")]
    Credential(#[from] CredentialError),

    #[error("Store error: {0}")]
    Store(#[from] StoreError),
}

/// Errors produced during credential or schema validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// One or more fields on the credential itself are invalid.
    #[error("Credential is structurally invalid: {reason}")]
    InvalidCredential { reason: String },

    /// The credential's claims do not conform to its JSON Schema.
    #[error("Claims do not conform to schema '{schema_id}': {details}")]
    SchemaMismatch { schema_id: String, details: String },

    /// The JSON Schema document itself is malformed and could not be compiled.
    #[error("JSON Schema is invalid: {reason}")]
    InvalidJsonSchema { reason: String },
}

/// Errors specific to credential lifecycle operations.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("Credential has been revoked")]
    Revoked,

    #[error("Credential has been suspended")]
    Suspended,

    #[error("Credential is already active")]
    AlreadyActive,
}
/// Errors that can occur during credential repository operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// No credential with the given ID exists in the store.
    #[error("credential not found: {0}")]
    NotFound(String),

    /// A credential with the given ID already exists in the store.
    #[error("credential already exists: {0}")]
    DuplicateId(String),

    /// Credential payload encryption failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Credential payload decryption failed (wrong key or tampered data).
    #[error("decryption error: {0}")]
    Decryption(String),

    /// An underlying storage error occurred.
    #[error("storage error: {0}")]
    Storage(#[from] Box<dyn std::error::Error + Send + Sync>),
}
