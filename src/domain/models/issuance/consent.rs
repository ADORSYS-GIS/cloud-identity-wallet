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

/// Consent domain errors.
#[derive(thiserror::Error, Debug)]
pub enum ConsentError {
    #[error("Session {0} does not exist")]
    NotFound(String),

    #[error("Session is not in awaiting_consent state")]
    InvalidState,

    #[error("Failed to build authorization URL: {0}")]
    AuthorizationUrlFailed(String),

    #[error("Session storage error: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Event publishing failed: {0}")]
    EventPublishing(String),
}