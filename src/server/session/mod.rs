//! Session management for the server layer.

pub mod service;
pub mod store;

#[cfg(feature = "session-memory")]
pub mod memory;

#[cfg(feature = "session-redis")]
pub mod redis;

pub use service::SessionManager;
pub use store::{SessionStore, SessionStoreError};
