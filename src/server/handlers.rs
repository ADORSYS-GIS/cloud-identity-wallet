mod consent;
mod health;
mod root;
mod tenant;

pub use consent::submit_consent;
pub use health::health_check;
pub use root::home;
pub use tenant::register_tenant;
