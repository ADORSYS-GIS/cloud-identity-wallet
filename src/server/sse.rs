use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingStep {
    ExchangingToken,
    RequestingCredential,
    AwaitingDeferredCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorStep {
    OfferResolution,
    Metadata,
    Authorization,
    Token,
    CredentialRequest,
    DeferredCredential,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SseEvent {
    Processing {
        session_id: String,
        step: ProcessingStep,
    },
    Completed {
        session_id: String,
        credential_ids: Vec<String>,
        credential_types: Vec<String>,
    },
    Failed {
        session_id: String,
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_description: Option<String>,
        step: ErrorStep,
    },
}

impl SseEvent {
    pub fn processing(session_id: &str, step: ProcessingStep) -> Self {
        Self::Processing {
            session_id: session_id.to_string(),
            step,
        }
    }

    pub fn completed(
        session_id: &str,
        credential_ids: Vec<String>,
        credential_types: Vec<String>,
    ) -> Self {
        Self::Completed {
            session_id: session_id.to_string(),
            credential_ids,
            credential_types,
        }
    }

    pub fn failed(
        session_id: &str,
        error: &str,
        error_description: Option<&str>,
        step: ErrorStep,
    ) -> Self {
        Self::Failed {
            session_id: session_id.to_string(),
            error: error.to_string(),
            error_description: error_description.map(|s| s.to_string()),
            step,
        }
    }

    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Processing { .. } => "processing",
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn session_id(&self) -> &str {
        match self {
            Self::Processing { session_id, .. } => session_id,
            Self::Completed { session_id, .. } => session_id,
            Self::Failed { session_id, .. } => session_id,
        }
    }
}
