use super::ports::TenantRepository;
use std::sync::Arc;

pub struct Service {
    pub tenant_repo: Arc<dyn TenantRepository>,
}

impl Service {
    pub fn new(tenant_repo: Arc<dyn TenantRepository>) -> Self {
        Self { tenant_repo }
    }
}
