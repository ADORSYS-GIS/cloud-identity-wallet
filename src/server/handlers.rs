mod health;
mod root;
mod tenant;

// Export handlers for use in the server
pub use health::health_check;
pub use root::home;
pub use tenant::register_tenant;
