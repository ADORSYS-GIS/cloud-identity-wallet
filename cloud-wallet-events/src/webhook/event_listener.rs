use crate::EventError;
use crate::events::Event;
use crate::traits::{Consumer, EventHandler, SubscriptionConfig};
use crate::webhook::delivery_service::{DeliveryQueue, QueuedDelivery};
use crate::webhook::payload_mapper::PayloadMapper;
use crate::webhook::subscription_repository::SubscriptionRepository;
use std::sync::Arc;

/// Bridges the event bus to the webhook delivery queue.
///
/// Topics to subscribe to are supplied by the caller at construction time,
/// keeping this library free of any domain-specific hardcoding.
///
/// Event-to-payload transformation is delegated to the caller-supplied
/// [`PayloadMapper`], and subscription lookup is delegated to the
/// [`SubscriptionRepository`], so neither domain knowledge nor storage
/// strategy is baked into this struct.
pub struct EventListener {
    repository: Arc<dyn SubscriptionRepository>,

    payload_mapper: Arc<dyn PayloadMapper>,

    delivery_queue: Arc<DeliveryQueue>,

    consumer: Arc<dyn Consumer>,

    /// Event-bus topics this listener will subscribe to.
    topics: Vec<String>,
}

impl EventListener {
    /// Create a new `EventListener`.
    ///
    /// # Arguments
    ///
    /// * `consumer` — Event-bus consumer used to subscribe to topics.
    /// * `repository` — Where to look up subscriptions matching each event.
    /// * `payload_mapper` — Transforms an [`Event`] into a `WebhookPayload`
    ///   JSON string. Use [`DefaultPayloadMapper`] or supply your own.
    /// * `delivery_queue` — Retry buffer onto which failed deliveries are
    ///   pushed. Successful first-attempt deliveries never touch this queue.
    /// * `topics` — Topic names to subscribe to on the event bus. The caller
    ///   controls which topics are relevant; this library imposes no opinion.
    ///
    /// [`DefaultPayloadMapper`]: crate::webhook::payload_mapper::DefaultPayloadMapper
    pub fn new(
        consumer: Arc<dyn Consumer>,
        repository: Arc<dyn SubscriptionRepository>,
        payload_mapper: Arc<dyn PayloadMapper>,
        delivery_queue: Arc<DeliveryQueue>,
        topics: Vec<String>,
    ) -> Self {
        Self {
            repository,
            payload_mapper,
            delivery_queue,
            consumer,
            topics,
        }
    }

    /// Start listening on the configured topics.
    pub async fn start(&self) -> Result<(), ListenerError> {
        let topics = self.topics.clone();
        let repository = self.repository.clone();
        let payload_mapper = self.payload_mapper.clone();
        let delivery_queue = self.delivery_queue.clone();

        let handler: EventHandler = Arc::new(move |event: Event| {
            let repository = repository.clone();
            let payload_mapper = payload_mapper.clone();
            let delivery_queue = delivery_queue.clone();

            Box::pin(async move {
                Self::handle_event(event, repository, payload_mapper, delivery_queue).await
            })
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
        repository: Arc<dyn SubscriptionRepository>,
        payload_mapper: Arc<dyn PayloadMapper>,
        delivery_queue: Arc<DeliveryQueue>,
    ) -> Result<(), EventError> {
        Self::enqueue_for_matching_subscriptions(
            &event,
            &repository,
            &payload_mapper,
            &delivery_queue,
        )
        .await;
        Ok(())
    }

    /// Fan out one event to every matching subscription.
    pub(crate) async fn enqueue_for_matching_subscriptions(
        event: &Event,
        repository: &Arc<dyn SubscriptionRepository>,
        payload_mapper: &Arc<dyn PayloadMapper>,
        delivery_queue: &Arc<DeliveryQueue>,
    ) {
        let event_type = event.event_type.as_str();
        let matching = repository.find_for_event(event_type).await;

        for sub in &matching {
            let webhook_payload = match payload_mapper.map(event, &sub.id) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let payload_bytes = match webhook_payload.to_json() {
                Ok(j) => j.into_bytes(),
                Err(_) => continue,
            };

            let delivery = QueuedDelivery::new(
                sub.id.clone(),
                event.id.to_string(),
                event_type.to_string(),
                payload_bytes,
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
    use crate::webhook::delivery_service::DeliveryQueue;
    use crate::webhook::payload_mapper::DefaultPayloadMapper;
    use crate::webhook::schemas::WebhookPayload;
    use crate::webhook::subscription::{WebhookAuth, WebhookSubscription};
    use crate::webhook::subscription_repository::InMemorySubscriptionRepository;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;

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

    fn default_mapper() -> Arc<dyn PayloadMapper> {
        Arc::new(DefaultPayloadMapper)
    }

    async fn repo_with(subs: Vec<WebhookSubscription>) -> Arc<dyn SubscriptionRepository> {
        let repo = Arc::new(InMemorySubscriptionRepository::new());
        for sub in subs {
            repo.upsert(sub).await;
        }
        repo
    }

    #[tokio::test]
    async fn test_enqueue_matching_subscription() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub =
            WebhookSubscription::new("sub-1", "https://example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_to(vec![EventType::CREDENTIAL_STORED.to_string()]);

        let repo = repo_with(vec![sub]).await;
        let event = make_credential_stored_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &repo, &default_mapper(), &queue)
            .await;

        assert_eq!(queue.size().await, 1);
        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.subscription_id, "sub-1");
        assert_eq!(delivery.event_type, EventType::CREDENTIAL_STORED);

        // payload is Vec<u8> — parse it back to verify contents
        let payload: WebhookPayload =
            serde_json::from_slice(&delivery.payload).expect("parse payload");
        assert_eq!(payload.webhook_id, "sub-1");
        assert_eq!(payload.data["wallet_id"], "wallet-test");
        assert_eq!(payload.data["correlation_id"], "corr-test");
    }

    #[tokio::test]
    async fn test_no_enqueue_when_subscription_does_not_match() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub =
            WebhookSubscription::new("sub-2", "https://example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_to(vec![EventType::KEY_CREATED.to_string()]);

        let repo = repo_with(vec![sub]).await;
        let event = make_credential_stored_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &repo, &default_mapper(), &queue)
            .await;

        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_enqueue_for_multiple_subscriptions() {
        let queue = Arc::new(DeliveryQueue::new());

        let sub1 =
            WebhookSubscription::new("sub-1", "https://a.example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_all();

        let sub2 =
            WebhookSubscription::new("sub-2", "https://b.example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_to(vec![EventType::CREDENTIAL_STORED.to_string()]);

        let sub3 =
            WebhookSubscription::new("sub-3", "https://c.example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_to(vec![EventType::KEY_CREATED.to_string()]);

        let repo = repo_with(vec![sub1, sub2, sub3]).await;
        let event = make_credential_stored_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &repo, &default_mapper(), &queue)
            .await;

        // sub-1 (catch-all) + sub-2 (credential.stored) match; sub-3 does not.
        assert_eq!(queue.size().await, 2);
    }

    #[tokio::test]
    async fn test_each_subscription_gets_its_own_webhook_id() {
        let queue = Arc::new(DeliveryQueue::new());

        let sub1 =
            WebhookSubscription::new("sub-a", "https://a.example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_all();

        let sub2 =
            WebhookSubscription::new("sub-b", "https://b.example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_all();

        let repo = repo_with(vec![sub1, sub2]).await;
        let event = make_credential_stored_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &repo, &default_mapper(), &queue)
            .await;

        assert_eq!(queue.size().await, 2);

        let d1 = queue.dequeue().await.unwrap();
        let d2 = queue.dequeue().await.unwrap();

        let p1: WebhookPayload = serde_json::from_slice(&d1.payload).unwrap();
        let p2: WebhookPayload = serde_json::from_slice(&d2.payload).unwrap();

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

        let sub =
            WebhookSubscription::new("sub-e2e", "https://example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_all();

        let repo = repo_with(vec![sub]).await;
        let queue = Arc::new(DeliveryQueue::new());
        let topics = vec!["wallet.credential".to_string()];

        let listener = EventListener::new(consumer, repo, default_mapper(), queue.clone(), topics);
        listener.start().await.expect("listener start");

        assert_eq!(queue.size().await, 1);

        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.event_id, event_id);
        assert_eq!(delivery.subscription_id, "sub-e2e");
    }

    #[tokio::test]
    async fn test_listener_subscribes_to_caller_supplied_topics() {
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
            Arc::new(InMemorySubscriptionRepository::new()),
            default_mapper(),
            Arc::new(DeliveryQueue::new()),
            topics.clone(),
        );

        listener.start().await.expect("listener start");

        let captured = consumer.captured.lock().unwrap().clone();
        assert_eq!(captured, topics);
    }

    #[tokio::test]
    async fn test_key_event_does_not_match_credential_subscription() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub =
            WebhookSubscription::new("sub-cred", "https://example.com/webhook", WebhookAuth::None)
                .unwrap()
                .subscribe_to(vec![EventType::CREDENTIAL_STORED.to_string()]);

        let repo = repo_with(vec![sub]).await;
        let event = make_key_created_event();

        EventListener::enqueue_for_matching_subscriptions(&event, &repo, &default_mapper(), &queue)
            .await;

        assert!(queue.is_empty().await);
    }
}
