//! HTTP handlers for issuance-related endpoints.

mod consent;
mod tx_code;

pub use consent::submit_consent;
pub use tx_code::submit_transaction_code;
