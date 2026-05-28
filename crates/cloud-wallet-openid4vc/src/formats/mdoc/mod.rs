//! mDoc (ISO 18013-5) parsing support.
//!
//! This module provides foundational CBOR parsing for `mso_mdoc` credentials
//! returned by OpenID4VCI issuers. The entry point is [`ParsedMdoc::parse`],
//! which decodes a base64url-encoded `IssuerSigned` structure into a typed
//! [`ParsedMdoc`].
//!
//! # References
//!
//! - ISO/IEC 18013-5 — `IssuerSigned`, `MSO`, `ValidityInfo` CBOR structures
//! - [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — CBOR
//! - [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) — COSE_Sign1

pub mod error;
mod parser;
#[cfg(test)]
mod tests;

pub use error::{MdocError, Result};
pub use parser::{IssuerSignedItem, ParsedMdoc};
