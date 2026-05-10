mod health;
mod issuance;
mod root;
mod tenant;

// Export handlers for use in the server
pub use health::health_check;
pub use issuance::{
    authorization_callback, get_credential, get_session_events, list_credentials, start_issuance,
    submit_consent, submit_transaction_code,
};
pub use root::home;
pub use tenant::register_tenant;
