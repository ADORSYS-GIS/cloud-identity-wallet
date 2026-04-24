use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
    pub accepted: bool,
    #[serde(default)]
    pub selected_configuration_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub session_id: String,
    pub next_action: NextAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    Redirect,
    ProvideTxCode,
    None,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct ConsentErrorResponse {
    pub error: &'static str,
    pub error_description: String,
}
