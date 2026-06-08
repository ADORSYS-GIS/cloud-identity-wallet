//! OpenID4VP (OpenID for Verifiable Presentations) implementation.
//!
//! This module implements the OpenID4VP specification for verifiable presentations,
//! enabling the Wallet to respond to presentation requests from Verifiers.

pub mod authorization;
pub mod client_id;
pub mod dcql;
pub mod error;
pub mod metadata;
pub mod transaction_data;

pub use error::*;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Supported transaction data types per OpenID4VP Section 8.4.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDataType {
    /// OpenID4VP transaction data type.
    #[serde(rename = "openid4vp")]
    Openid4vp,
    /// Extension point for other transaction data types.
    #[serde(untagged)]
    Other(String),
}

impl TransactionDataType {
    /// Returns true if this is a supported transaction data type.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Openid4vp)
    }
}

impl std::fmt::Display for TransactionDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Openid4vp => write!(f, "openid4vp"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Transaction data entry as decoded from base64url.
///
/// Section 8.4 requires each entry to be base64url-decoded into a JSON object
/// with at least `type` and a non-empty `credential_ids` array referencing DCQL credential IDs.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionDataEntry {
    /// REQUIRED. The transaction data type.
    #[serde(rename = "type")]
    pub data_type: TransactionDataType,

    pub credential_ids: Vec<String>,
}
