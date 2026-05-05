//! HTTP handlers for issuance-related endpoints.

mod consent;

pub(crate) use consent::submit_consent;
