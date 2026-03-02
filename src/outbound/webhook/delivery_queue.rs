use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::schemas::{DeliveryState, DeliveryStatus};

/// In-memory queue for webhook deliveries
#[derive(Debug, Clone)]
pub struct DeliveryQueue {
    /// Pending deliveries waiting to be sent
    pending: Arc<RwLock<VecDeque<QueuedDelivery>>>,

    /// Delivery status history (kept for a limited time)
    history: Arc<RwLock<HashMap<String, Vec<DeliveryStatus>>>>,
}

/// A queued webhook delivery
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDelivery {
    pub subscription_id: String,

    pub event_id: String,

    pub event_type: String,

    pub payload: String,

    pub attempt: u32,

    /// Webhook URL
    pub url: String,
}

impl QueuedDelivery {
    /// Create a new queued delivery
    pub fn new(
        subscription_id: String,
        event_id: String,
        event_type: String,
        payload: String,
        url: String,
    ) -> Self {
        Self {
            subscription_id,
            event_id,
            event_type,
            payload,
            attempt: 0,
            url,
        }
    }

    pub fn next_attempt(mut self) -> Self {
        self.attempt += 1;
        self
    }
}

impl DeliveryQueue {
    /// Create a new delivery queue
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(VecDeque::new())),
            history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enqueue a delivery
    pub async fn enqueue(&self, delivery: QueuedDelivery) {
        let mut pending = self.pending.write().await;
        debug!(
            event_id = %delivery.event_id,
            subscription_id = %delivery.subscription_id,
            "Enqueuing delivery"
        );
        pending.push_back(delivery);
    }

    /// Dequeue the next delivery
    pub async fn dequeue(&self) -> Option<QueuedDelivery> {
        let mut pending = self.pending.write().await;
        let delivery = pending.pop_front();

        if let Some(ref d) = delivery {
            debug!(
                event_id = %d.event_id,
                subscription_id = %d.subscription_id,
                "Dequeued delivery"
            );
        }

        delivery
    }

    /// Re-queue a delivery for retry
    pub async fn requeue(&self, delivery: QueuedDelivery) {
        let updated = delivery.next_attempt();
        debug!(
            event_id = %updated.event_id,
            attempt = %updated.attempt,
            "Re-queuing delivery for retry"
        );
        self.enqueue(updated).await;
    }

    /// Get queue size
    pub async fn size(&self) -> usize {
        let pending = self.pending.read().await;
        pending.len()
    }

    /// Check if queue is empty
    pub async fn is_empty(&self) -> bool {
        let pending = self.pending.read().await;
        pending.is_empty()
    }

    /// Clear all pending deliveries
    pub async fn clear(&self) {
        let mut pending = self.pending.write().await;
        let count = pending.len();
        pending.clear();
        info!(cleared_count = count, "Cleared delivery queue");
    }

    /// Record delivery status in history
    pub async fn record_status(&self, status: DeliveryStatus) {
        let mut history = self.history.write().await;

        let key = format!("{}:{}", status.subscription_id, status.event_id);
        let entries = history.entry(key).or_insert_with(Vec::new);

        entries.push(status);
    }

    /// Get delivery history for an event
    pub async fn get_history(&self, subscription_id: &str, event_id: &str) -> Vec<DeliveryStatus> {
        let history = self.history.read().await;
        let key = format!("{subscription_id}:{event_id}");

        history.get(&key).cloned().unwrap_or_default()
    }

    /// Get latest status for an event
    pub async fn get_latest_status(
        &self,
        subscription_id: &str,
        event_id: &str,
    ) -> Option<DeliveryStatus> {
        let history = self.get_history(subscription_id, event_id).await;
        history.last().cloned()
    }

    /// Count deliveries by state
    pub async fn count_by_state(&self, subscription_id: &str) -> HashMap<DeliveryState, usize> {
        let history = self.history.read().await;
        let mut counts: HashMap<DeliveryState, usize> = HashMap::new();

        for (key, statuses) in history.iter() {
            if key.starts_with(&format!("{subscription_id}:"))
                && let Some(latest) = statuses.last()
            {
                *counts.entry(latest.status).or_insert(0) += 1;
            }
        }

        counts
    }
}

impl Default for DeliveryQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_delivery() -> QueuedDelivery {
        QueuedDelivery::new(
            "sub-123".to_string(),
            "evt-456".to_string(),
            "credential.stored".to_string(),
            r#"{"test":"data"}"#.to_string(),
            "https://example.com/webhook".to_string(),
        )
    }

    #[tokio::test]
    async fn test_queue_enqueue_dequeue() {
        let queue = DeliveryQueue::new();
        let delivery = create_test_delivery();

        assert!(queue.is_empty().await);

        queue.enqueue(delivery.clone()).await;
        assert_eq!(queue.size().await, 1);
        assert!(!queue.is_empty().await);

        let dequeued = queue.dequeue().await;
        assert!(matches!(dequeued, Some(d) if d == delivery));
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_queue_fifo_order() {
        let queue = DeliveryQueue::new();

        let d1 = QueuedDelivery::new(
            "sub-1".to_string(),
            "evt-1".to_string(),
            "test".to_string(),
            "{}".to_string(),
            "url".to_string(),
        );

        let d2 = QueuedDelivery::new(
            "sub-2".to_string(),
            "evt-2".to_string(),
            "test".to_string(),
            "{}".to_string(),
            "url".to_string(),
        );

        queue.enqueue(d1.clone()).await;
        queue.enqueue(d2.clone()).await;

        let first = queue.dequeue().await;
        assert!(matches!(first, Some(d) if d == d1));

        let second = queue.dequeue().await;
        assert!(matches!(second, Some(d) if d == d2));
    }

    #[tokio::test]
    async fn test_requeue_increments_attempt() {
        let queue = DeliveryQueue::new();
        let delivery = create_test_delivery();

        assert_eq!(delivery.attempt, 0);

        queue.requeue(delivery.clone()).await;

        let requeued = queue.dequeue().await;
        assert!(matches!(requeued, Some(d) if d.attempt == 1));
    }

    #[tokio::test]
    async fn test_clear_queue() {
        let queue = DeliveryQueue::new();

        queue.enqueue(create_test_delivery()).await;
        queue.enqueue(create_test_delivery()).await;
        assert_eq!(queue.size().await, 2);

        queue.clear().await;
        assert_eq!(queue.size().await, 0);
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_record_and_get_history() {
        let queue = DeliveryQueue::new();

        let status = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string());

        queue.record_status(status.clone()).await;

        let history = queue.get_history("sub-123", "evt-456").await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].event_id, "evt-456");
    }

    #[tokio::test]
    async fn test_get_latest_status() {
        let queue = DeliveryQueue::new();

        let status1 = DeliveryStatus::pending("sub-123".to_string(), "evt-456".to_string());
        let status2 = status1.clone().in_progress(1).succeeded(200, 100);

        queue.record_status(status1).await;
        queue.record_status(status2.clone()).await;

        let latest = queue.get_latest_status("sub-123", "evt-456").await;
        assert!(matches!(latest, Some(s) if s.status == DeliveryState::Succeeded));
    }

    #[tokio::test]
    async fn test_count_by_state() {
        let queue = DeliveryQueue::new();

        // Record various states
        queue
            .record_status(
                DeliveryStatus::pending("sub-123".to_string(), "evt-1".to_string())
                    .succeeded(200, 100),
            )
            .await;

        queue
            .record_status(
                DeliveryStatus::pending("sub-123".to_string(), "evt-2".to_string())
                    .succeeded(200, 100),
            )
            .await;

        queue
            .record_status(
                DeliveryStatus::pending("sub-123".to_string(), "evt-3".to_string()).failed(
                    Some(500),
                    "error".to_string(),
                    None,
                ),
            )
            .await;

        let counts = queue.count_by_state("sub-123").await;

        assert_eq!(counts.get(&DeliveryState::Succeeded), Some(&2));
        assert_eq!(counts.get(&DeliveryState::Failed), Some(&1));
    }
}
