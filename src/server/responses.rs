use serde::Serialize;

/// Generic response structure shared by all API responses.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseBody<T: Serialize> {
    status_code: u16,
    data: T,
}
