#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Tenants {
    pub id: uuid::Uuid,
    pub name: String,
    // TODO: More fields will be added later
}
