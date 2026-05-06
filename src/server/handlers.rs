mod credential;
mod health;
mod issuance;
mod root;
mod tenant;

// Export handlers for use in the server
pub use credential::{get_credential, list_credentials};
pub use health::health_check;
pub use issuance::start_issuance;
pub use issuance::submit_consent;
pub use root::home;
pub use tenant::register_tenant;
