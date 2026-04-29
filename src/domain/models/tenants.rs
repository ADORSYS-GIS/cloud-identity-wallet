use std::str::FromStr;

use cloud_wallet_crypto::secret::Secret;
use color_eyre::eyre::Report;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during tenant management operations.
#[derive(Debug, Error)]
pub enum TenantError {
    #[error("Storage backend error: {0}")]
    Backend(#[from] Report),

    #[error("Encryption or decryption error: {0}")]
    Encryption(Box<dyn std::error::Error + Send + Sync>),

    #[error("Invalid tenant name: {0}")]
    InvalidName(String),

    #[error("Invalid stored data: {0}")]
    InvalidData(String),

    #[error("Tenant not found: {id}")]
    NotFound { id: Uuid },
}

/// Tenant key material
#[derive(Debug, Clone)]
pub struct TenantKey {
    pub algorithm: SignAlgorithm,
    pub der_bytes: Secret,
}

/// Signature algorithm for tenant key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    Ecdsa,
    Rsa,
    EdDsa,
}

impl SignAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::Rsa => "rsa",
            Self::EdDsa => "eddsa",
        }
    }
}

impl FromStr for SignAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ecdsa" => Ok(Self::Ecdsa),
            "rsa" => Ok(Self::Rsa),
            "eddsa" => Ok(Self::EdDsa),
            _ => Err("Invalid signature algorithm"),
        }
    }
}

impl std::fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A validated tenant name string.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TenantName(String);

impl TenantName {
    /// Creates a new TenantName from a String.
    pub fn new(name: impl Into<String>) -> Result<Self, String> {
        let trimmed = name.into().trim().to_string();

        if trimmed.is_empty() {
            return Err("name cannot be empty".into());
        }
        if trimmed.len() > 255 {
            return Err("name must not exceed 255 characters".into());
        }

        Ok(Self(trimmed))
    }

    /// Returns the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Request body for tenant registration.
#[derive(Debug, Deserialize)]
pub struct RegisterTenantRequest {
    /// The tenant name as a raw string. Will be validated and trimmed.
    pub name: String,
}

/// Response body for successful tenant registration.
#[derive(Debug, Serialize)]
pub struct TenantResponse {
    pub tenant_id: String,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_name() {
        let result = TenantName::new("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name cannot be empty");
    }

    #[test]
    fn rejects_whitespace_only_name() {
        let result = TenantName::new("   ");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name cannot be empty");
    }

    #[test]
    fn rejects_256_char_name() {
        let name = "a".repeat(256);
        let result = TenantName::new(&name);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name must not exceed 255 characters");
    }

    #[test]
    fn accepts_255_char_name() {
        let name = "a".repeat(255);
        let result = TenantName::new(&name);
        assert!(result.is_ok());
    }

    #[test]
    fn trims_whitespace() {
        let result = TenantName::new("  test name  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "test name");
    }

    #[test]
    fn accepts_valid_name() {
        let result = TenantName::new("Acme Corporation");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "Acme Corporation");
    }
}
