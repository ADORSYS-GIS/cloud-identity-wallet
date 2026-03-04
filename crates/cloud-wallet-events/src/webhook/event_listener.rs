use crate::EventError;
use crate::events::Event;
use crate::traits::{Consumer, EventHandler, SubscriptionConfig};
use crate::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
use crate::webhook::schemas::WebhookPayload;
use crate::webhook::subscription::WebhookSubscription;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Bridges the event bus to the webhook delivery queue.
pub struct EventListener {
    subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,

    delivery_queue: Arc<DeliveryQueue>,

    consumer: Arc<dyn Consumer>,
}

impl EventListener {
    pub fn new(
        consumer: Arc<dyn Consumer>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
    ) -> Self {
        Self {
            subscriptions,
            delivery_queue,
            consumer,
        }
    }

    /// Start listening on all wallet topics.
    pub async fn start(&self) -> Result<(), ListenerError> {
        let topics = vec![
            "wallet.credential".to_string(),
            "wallet.presentation".to_string(),
            "wallet.key".to_string(),
        ];

        info!(topic_count = topics.len(), "Starting event listener");

        let subscriptions = self.subscriptions.clone();
        let delivery_queue = self.delivery_queue.clone();

        let handler: EventHandler = Arc::new(move |event: Event| {
            let subscriptions = subscriptions.clone();
            let delivery_queue = delivery_queue.clone();

            Box::pin(async move { Self::handle_event(event, subscriptions, delivery_queue).await })
        });

        self.consumer
            .subscribe(SubscriptionConfig { topics }, handler)
            .await
            .map_err(|e| ListenerError::SubscribeFailed {
                reason: e.to_string(),
            })?;

        info!("Event listener started");
        Ok(())
    }

    async fn handle_event(
        event: Event,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
    ) -> Result<(), EventError> {
        let event_type = event.event_type.as_str();
        debug!(
            event_type = %event_type,
            event_id = %event.id,
            "Received event"
        );

        let payload = match Self::build_payload(&event) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    event_id = %event.id,
                    error = %e,
                    "Failed to serialise event into webhook payload – skipping"
                );
                return Err(EventError::SerializationError(e));
            }
        };

        Self::enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &delivery_queue)
            .await;

        Ok(())
    }

    /// Serialise an `Event` into a `WebhookPayload` JSON string.
    pub(crate) fn build_payload(event: &Event) -> Result<String, String> {
        let payload = WebhookPayload::new(
            event.id.to_string(),
            event.event_type.as_str().to_string(),
            event.timestamp,
            event
                .metadata
                .get("wallet_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            event
                .metadata
                .get("correlation_id")
                .and_then(|v| v.as_str())
                .unwrap_or(&event.id.to_string())
                .to_string(),
            event.payload.clone(),
        );

        payload.to_json().map_err(|e| e.to_string())
    }

    /// Fan out one event to every matching subscription.
    pub(crate) async fn enqueue_for_matching_subscriptions(
        event: &Event,
        payload_json: &str,
        subscriptions: &Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: &Arc<DeliveryQueue>,
    ) {
        let event_type = event.event_type.as_str();

        let subs = subscriptions.read().await;
        let mut enqueued = 0usize;

        for sub in subs.iter() {
            if !sub.matches_event(event_type) {
                continue;
            }

            let delivery = QueuedDelivery::new(
                sub.id.clone(),
                event.id.to_string(),
                event_type.to_string(),
                payload_json.to_string(),
                sub.url.clone(),
            );

            delivery_queue.enqueue(delivery).await;
            enqueued += 1;

            debug!(
                subscription_id = %sub.id,
                event_type = %event_type,
                "Delivery enqueued"
            );
        }

        if enqueued == 0 {
            debug!(
                event_type = %event_type,
                "No subscriptions matched – event dropped"
            );
        }
    }
}

/// Errors that can occur in the `EventListener`.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("Failed to subscribe: {reason}")]
    SubscribeFailed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EventError;
    use crate::events::{Event, EventType};
    use crate::traits::{Consumer, EventHandler, SubscriptionConfig};
    use crate::webhook::delivery_queue::DeliveryQueue;
    use crate::webhook::schemas::WebhookPayload;
    use crate::webhook::subscription::{WebhookAuth, WebhookSubscription};
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    struct MockConsumer {
        events: Vec<Event>,
    }

    #[async_trait]
    impl Consumer for MockConsumer {
        async fn subscribe(
            &self,
            _config: SubscriptionConfig,
            handler: EventHandler,
        ) -> Result<(), EventError> {
            for event in &self.events {
                handler(event.clone()).await?;
            }
            Ok(())
        }
    }

    fn make_credential_stored_event() -> Event {
        Event::new(
            EventType::new(EventType::CREDENTIAL_STORED),
            json!({
                "credential_id": "cred-1",
                "credential_type": "UniversityDegree",
                "issuer": "https://uni.example.com"
            }),
        )
        .with_metadata("wallet_id", "wallet-test")
        .with_metadata("correlation_id", "corr-test")
    }

    fn make_key_created_event() -> Event {
        Event::new(
            EventType::new(EventType::KEY_CREATED),
            json!({
                "key_id": "key-1",
                "kid": "did:example:1#key-1",
                "key_type": "Ed25519"
            }),
        )
        .with_metadata("wallet_id", "wallet-test")
        .with_metadata("correlation_id", "corr-key")
    }

    #[test]
    fn test_build_payload_serialises_correctly() {
        let event = make_credential_stored_event();
        let json = EventListener::build_payload(&event).expect("build payload");

        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");

        assert_eq!(payload.event_id, event.id.to_string());
        assert_eq!(payload.event_type, EventType::CREDENTIAL_STORED);
        assert_eq!(payload.wallet_id, "wallet-test");
        assert_eq!(payload.correlation_id, "corr-test");
    }

    #[test]
    fn test_build_payload_key_event() {
        let event = make_key_created_event();
        let json = EventListener::build_payload(&event).expect("build payload");
        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");
        assert_eq!(payload.event_type, EventType::KEY_CREATED);
    }

    #[tokio::test]
    async fn test_enqueue_matching_subscription() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = WebhookSubscription::new(
            "sub-1".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec![EventType::CREDENTIAL_STORED.to_string()]);

        let subscriptions = Arc::new(RwLock::new(vec![sub]));

        let event = make_credential_stored_event();
        let payload = EventListener::build_payload(&event).expect("build payload");

        EventListener::enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue)
            .await;

        assert_eq!(queue.size().await, 1);
        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.subscription_id, "sub-1");
        assert_eq!(delivery.event_type, EventType::CREDENTIAL_STORED);
    }

    #[tokio::test]
    async fn test_no_enqueue_when_subscription_does_not_match() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = WebhookSubscription::new(
            "sub-2".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec![EventType::KEY_CREATED.to_string()]);

        let subscriptions = Arc::new(RwLock::new(vec![sub]));
        let event = make_credential_stored_event();
        let payload = EventListener::build_payload(&event).expect("build payload");

        EventListener::enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue)
            .await;

        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_enqueue_for_multiple_subscriptions() {
        let queue = Arc::new(DeliveryQueue::new());

        let sub1 = WebhookSubscription::new(
            "sub-1".to_string(),
            "https://a.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        let sub2 = WebhookSubscription::new(
            "sub-2".to_string(),
            "https://b.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec![EventType::CREDENTIAL_STORED.to_string()]);

        let sub3 = WebhookSubscription::new(
            "sub-3".to_string(),
            "https://c.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec![EventType::KEY_CREATED.to_string()]);

        let subscriptions = Arc::new(RwLock::new(vec![sub1, sub2, sub3]));
        let event = make_credential_stored_event();
        let payload = EventListener::build_payload(&event).expect("build payload");

        EventListener::enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue)
            .await;

        assert_eq!(queue.size().await, 2);
    }

    #[tokio::test]
    async fn test_listener_processes_events_end_to_end() {
        let event = make_credential_stored_event();
        let event_id = event.id.to_string();

        let consumer = Arc::new(MockConsumer {
            events: vec![event],
        });

        let sub = WebhookSubscription::new(
            "sub-e2e".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        let subscriptions = Arc::new(RwLock::new(vec![sub]));
        let queue = Arc::new(DeliveryQueue::new());

        let listener = EventListener::new(consumer, subscriptions, queue.clone());
        listener.start().await.expect("listener start");

        assert_eq!(queue.size().await, 1);

        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.event_id, event_id);
        assert_eq!(delivery.subscription_id, "sub-e2e");
    }
}
