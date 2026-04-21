use super::ports::TenantRepository;
use std::sync::Arc;

pub struct Service {
    pub tenant_repo: Arc<dyn TenantRepository>,
}

impl Service {
    pub fn new<T: TenantRepository>(tenant_repo: T) -> Self {
        Self {
            tenant_repo: Arc::new(tenant_repo),
        }
    }
}
