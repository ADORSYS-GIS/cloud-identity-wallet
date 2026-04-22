use crate::session::SessionStore;

#[derive(Debug, Clone)]
pub struct Service<S> {
    pub session: S,
}

impl<S: SessionStore> Service<S> {
    pub fn new(session: S) -> Self {
        Self { session }
    }
}
