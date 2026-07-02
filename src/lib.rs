#[cfg(all(
    feature = "sqlx",
    not(any(feature = "mysql", feature = "postgres", feature = "sqlite"))
))]
compile_error!("feature `sqlx` requires one of `mysql`, `postgres`, or `sqlite`");

pub mod config;
pub mod domain;
pub mod outbound;
pub mod server;
pub mod session;
pub mod setup;
pub mod telemetry;
pub mod utils;
