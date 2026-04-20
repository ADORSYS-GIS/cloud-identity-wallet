use std::sync::Arc;
use super::ports::TenantRepository;

pub struct Service {
    pub tenant_repo: Arc<dyn TenantRepository>,
}

impl Service {
    pub fn new(tenant_repo: Arc<dyn TenantRepository>) -> Self {
        Self { tenant_repo }
    }
}
