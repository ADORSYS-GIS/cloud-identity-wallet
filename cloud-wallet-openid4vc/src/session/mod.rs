//! Session management for OID4VC issuance and authorization flows.

pub mod model;
pub mod service;
pub mod store;

#[cfg(feature = "session-memory")]
pub mod memory;

#[cfg(feature = "session-redis")]
pub mod redis;

pub use service::SessionService;
pub use store::{SessionStore, SessionStoreError};
