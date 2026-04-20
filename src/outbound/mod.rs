/*
   Module `outbound` contains the canonical implementations of the ports traits
   by which external modules interact with the domain.
*/

mod tenant_repository;

pub use tenant_repository::SqlTenantRepository;
