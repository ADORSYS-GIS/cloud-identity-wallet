mod health;
mod issuance;
mod root;
mod tenant;

// Export handlers for use in the server
pub use health::health_check;
pub use issuance::authorization_callback;
pub use root::home;
pub use tenant::register_tenant;
