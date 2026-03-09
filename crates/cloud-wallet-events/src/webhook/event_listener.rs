use crate::EventError;
use crate::events::Event;
use crate::traits::{Consumer, EventHandler, SubscriptionConfig};
use crate::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
use crate::webhook::schemas::WebhookPayload;
use crate::webhook::subscription::WebhookSubscription;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bridges the event bus to the webhook delivery queue.
///
/// Topics to subscribe to are supplied by the caller at construction time,
/// keeping this library free of any domain-specific hardcoding.
pub struct EventListener {
    subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,

    delivery_queue: Arc<DeliveryQueue>,

    consumer: Arc<dyn Consumer>,

    /// Event-bus topics this listener will subscribe to.
    topics: Vec<String>,
}

impl EventListener {
    /// Create a new `EventListener`.
    pub fn new(
        consumer: Arc<dyn Consumer>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
        topics: Vec<String>,
    ) -> Self {
        Self {
            subscriptions,
            delivery_queue,
            consumer,
            topics,
        }
    }

    /// Start listening on the configured topics.
    pub async fn start(&self) -> Result<(), ListenerError> {
        let topics = self.topics.clone();

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

        Ok(())
    }

    async fn handle_event(
        event: Event,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
    ) -> Result<(), EventError> {
        Self::enqueue_for_matching_subscriptions(&event, &subscriptions, &delivery_queue).await;
        Ok(())
    }

    /// Serialise an `Event` into a `WebhookPayload` JSON string.
    pub(crate) fn build_payload(event: &Event, subscription_id: &str) -> Result<String, String> {
        let wallet_id = event
            .metadata
            .get("wallet_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let correlation_id = event
            .metadata
            .get("correlation_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.id.to_string())
            .to_string();

        let payload = WebhookPayload::new(
            event.id.to_string(),
            subscription_id.to_string(),
            event.timestamp,
            event.event_type.as_str().to_string(),
            wallet_id,
            correlation_id,
            event.payload.clone(),
        );

        payload.to_json().map_err(|e| e.to_string())
    }

    /// Fan out one event to every matching subscription.
    pub(crate) async fn enqueue_for_matching_subscriptions(
        event: &Event,
        subscriptions: &Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: &Arc<DeliveryQueue>,
    ) {
        let event_type = event.event_type.as_str();

        let subs = subscriptions.read().await;

        for sub in subs.iter() {
            if !sub.matches_event(event_type) {
                continue;
            }

            let payload_json = match Self::build_payload(event, &sub.id) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let delivery = QueuedDelivery::new(
                sub.id.clone(),
                event.id.to_string(),
                event_type.to_string(),
                payload_json,
                sub.url.clone(),
            );

            delivery_queue.enqueue(delivery).await;
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
        let json = EventListener::build_payload(&event, "sub-1").expect("build payload");

        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");

        assert_eq!(payload.delivery_id, event.id.to_string());
        assert_eq!(payload.webhook_id, "sub-1");
        assert_eq!(payload.event_type, EventType::CREDENTIAL_STORED);
        assert_eq!(payload.data["wallet_id"], "wallet-test");
        assert_eq!(payload.data["correlation_id"], "corr-test");
    }

    #[test]
    fn test_build_payload_key_event() {
        let event = make_key_created_event();
        let json = EventListener::build_payload(&event, "sub-1").expect("build payload");
        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");
        assert_eq!(payload.event_type, EventType::KEY_CREATED);
    }

    #[test]
    fn test_build_payload_missing_wallet_id_falls_back_to_unknown() {
        let event = Event::new(
            EventType::new(EventType::CREDENTIAL_STORED),
            json!({"credential_id": "cred-x"}),
        );
        let json = EventListener::build_payload(&event, "sub-1").expect("build payload");
        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");
        assert_eq!(payload.data["wallet_id"], "unknown");
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

        EventListener::enqueue_for_matching_subscriptions(&event, &subscriptions, &queue).await;

        assert_eq!(queue.size().await, 1);
        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.subscription_id, "sub-1");
        assert_eq!(delivery.event_type, EventType::CREDENTIAL_STORED);

        // Payload must use the reference schema field names
        let payload: WebhookPayload =
            serde_json::from_str(&delivery.payload).expect("parse payload");
        assert_eq!(payload.webhook_id, "sub-1");
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

        EventListener::enqueue_for_matching_subscriptions(&event, &subscriptions, &queue).await;

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

        EventListener::enqueue_for_matching_subscriptions(&event, &subscriptions, &queue).await;

        assert_eq!(queue.size().await, 2);
    }

    #[tokio::test]
    async fn test_each_subscription_gets_its_own_webhook_id() {
        // Each delivery must carry the matching subscription's ID as webhookID
        let queue = Arc::new(DeliveryQueue::new());

        let sub1 = WebhookSubscription::new(
            "sub-a".to_string(),
            "https://a.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        let sub2 = WebhookSubscription::new(
            "sub-b".to_string(),
            "https://b.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        let subscriptions = Arc::new(RwLock::new(vec![sub1, sub2]));
        let event = make_credential_stored_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &subscriptions, &queue).await;

        assert_eq!(queue.size().await, 2);

        let d1 = queue.dequeue().await.unwrap();
        let d2 = queue.dequeue().await.unwrap();

        let p1: WebhookPayload = serde_json::from_str(&d1.payload).unwrap();
        let p2: WebhookPayload = serde_json::from_str(&d2.payload).unwrap();

        let ids: std::collections::HashSet<_> =
            [p1.webhook_id.as_str(), p2.webhook_id.as_str()].into();
        assert!(ids.contains("sub-a"));
        assert!(ids.contains("sub-b"));
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
        let topics = vec!["wallet.credential".to_string()];

        let listener = EventListener::new(consumer, subscriptions, queue.clone(), topics);
        listener.start().await.expect("listener start");

        assert_eq!(queue.size().await, 1);

        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.event_id, event_id);
        assert_eq!(delivery.subscription_id, "sub-e2e");
    }

    #[tokio::test]
    async fn test_listener_subscribes_to_caller_supplied_topics() {
        // The listener must pass exactly the topics given by the caller to the consumer.
        struct TopicCapturingConsumer {
            captured: std::sync::Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl Consumer for TopicCapturingConsumer {
            async fn subscribe(
                &self,
                config: SubscriptionConfig,
                _handler: EventHandler,
            ) -> Result<(), EventError> {
                *self.captured.lock().unwrap() = config.topics;
                Ok(())
            }
        }

        let consumer = Arc::new(TopicCapturingConsumer {
            captured: std::sync::Mutex::new(vec![]),
        });

        let topics = vec!["custom.topic.a".to_string(), "custom.topic.b".to_string()];

        let listener = EventListener::new(
            consumer.clone(),
            Arc::new(RwLock::new(vec![])),
            Arc::new(DeliveryQueue::new()),
            topics.clone(),
        );

        listener.start().await.expect("listener start");

        let captured = consumer.captured.lock().unwrap().clone();
        assert_eq!(captured, topics);
    }
}
