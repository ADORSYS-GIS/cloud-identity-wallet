use serde::Serialize;
use tokio::sync::broadcast;

use crate::session::{FailureStep, ProcessingStep};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SseEvent {
    Processing {
        session_id: String,
        step: ProcessingStep,
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
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}
