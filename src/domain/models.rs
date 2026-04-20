//! Domain models for the wallet.

use color_eyre::eyre::Report;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export Tenant from cloud-wallet-openid4vc
pub use cloud_wallet_openid4vc::credential::tenants::Tenants as Tenant;

/// Errors that can occur during tenant operations.
#[derive(Debug, Error)]
pub enum TenantError {
    #[error("Storage backend error: {0}")]
    Backend(#[from] Report),

    #[error("Invalid tenant name: {0}")]
    InvalidName(String),
}

/// A validated tenant name string.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TenantName(String);

impl TenantName {
    /// Creates a new TenantName from a String.
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Validates and creates a TenantName from a string.
    /// 
    /// The name is trimmed, and must be non-empty and at most 255 characters.
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - The trimmed name is empty
    /// - The trimmed name exceeds 255 characters
    pub fn validate(name: &str) -> Result<Self, String> {
        let trimmed = name.trim().to_string();

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

impl From<String> for TenantName {
    fn from(name: String) -> Self {
        Self(name)
    }
}

impl AsRef<str> for TenantName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for TenantName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for TenantName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Request body for tenant registration.
#[derive(Debug, Deserialize)]
pub struct RegisterTenantRequest {
    pub name: TenantName,
}

/// Response body for successful tenant registration.
#[derive(Debug, Serialize)]
pub struct TenantResponse {
    pub tenant_id: String,
    pub name: TenantName,
}

/// Error response following RFC 7807 / OID4VCI conventions.
#[derive(Debug, Serialize)]
pub struct TenantErrorResponse {
    pub error: &'static str,
    pub error_description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_name() {
        let result = TenantName::validate("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name cannot be empty");
    }

    #[test]
    fn rejects_whitespace_only_name() {
        let result = TenantName::validate("   ");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name cannot be empty");
    }

    #[test]
    fn rejects_256_char_name() {
        let name = "a".repeat(256);
        let result = TenantName::validate(&name);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "name must not exceed 255 characters");
    }

    #[test]
    fn accepts_255_char_name() {
        let name = "a".repeat(255);
        let result = TenantName::validate(&name);
        assert!(result.is_ok());
    }

    #[test]
    fn trims_whitespace() {
        let result = TenantName::validate("  test name  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test name");
    }

    #[test]
    fn accepts_valid_name() {
        let result = TenantName::validate("Acme Corporation");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Acme Corporation");
    }
}
