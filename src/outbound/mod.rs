/*
   Module `outbound` contains the canonical implementations of the ports traits
   by which external modules interact with the domain.
*/

mod tenant;

pub use tenant::{MemoryTenantRepository, SqlTenantRepository};
