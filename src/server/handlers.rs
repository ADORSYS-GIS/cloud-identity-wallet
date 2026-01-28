mod health;
mod root;

// Export handlers for use in the server
pub use health::health_check;
pub use root::home;
