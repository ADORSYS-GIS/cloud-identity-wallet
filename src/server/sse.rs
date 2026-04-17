use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::domain::models::{FailureStep, ProcessingStep};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SseEvent {
    Processing {
        session_id: String,
        step: ProcessingStep,
    },
    Completed {
        session_id: String,
        credential_ids: Vec<Uuid>,
        credential_types: Vec<String>,
    },
    Failed {
        session_id: String,
        error: String,
        error_description: Option<String>,
        step: FailureStep,
    },
}

impl SseEvent {
    pub fn processing(session_id: String, step: ProcessingStep) -> Self {
        Self::Processing { session_id, step }
    }

    pub fn completed(
        session_id: String,
        credential_ids: Vec<Uuid>,
        credential_types: Vec<String>,
    ) -> Self {
        Self::Completed {
            session_id,
            credential_ids,
            credential_types,
        }
    }

    pub fn failed(
        session_id: String,
        error: String,
        error_description: Option<String>,
        step: FailureStep,
    ) -> Self {
        Self::Failed {
            session_id,
            error,
            error_description,
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

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Failed { .. })
    }
}

pub type EventSender = broadcast::Sender<SseEvent>;

#[derive(Debug, Clone)]
pub struct SseBroadcaster {
    senders: dashmap::DashMap<String, EventSender>,
}

impl SseBroadcaster {
    pub fn new() -> Self {
        Self {
            senders: dashmap::DashMap::new(),
        }
    }

    pub fn create_channel(&self, session_id: &str) -> broadcast::Receiver<SseEvent> {
        let (tx, rx) = broadcast::channel(16);
        self.senders.insert(session_id.to_string(), tx);
        rx
    }

    pub fn send(&self, session_id: &str, event: SseEvent) -> bool {
        if let Some(tx) = self.senders.get(session_id) {
            let _ = tx.send(event);
            true
        } else {
            false
        }
    }

    pub fn remove(&self, session_id: &str) {
        self.senders.remove(session_id);
    }

    pub fn get_sender(&self, session_id: &str) -> Option<EventSender> {
        self.senders
            .get(session_id)
            .map(|entry| entry.value().clone())
    }
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_sse_frame(event_type: &str, data: &str) -> String {
    format!("event: {event_type}\ndata: {data}\n\n")
}
