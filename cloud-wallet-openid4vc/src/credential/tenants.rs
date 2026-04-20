/// Represents a Tenant in the multi-tenant wallet ecosystem.
///
/// Each tenant operates as an isolated logical wallet, managing its own credentials, keys,
/// and configurations independently of other tenants on the same instance.
#[derive(Debug, Clone)]
pub struct Tenants {
    /// Unique identifier for the tenant.
    pub id: uuid::Uuid,
    /// Human-readable name of the tenant.
    pub name: String,
    /// Timestamp when the tenant was created.
    pub created_at: time::UtcDateTime,
    // TODO: More fields will be added later
}
