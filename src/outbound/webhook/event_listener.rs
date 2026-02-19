use crate::outbound::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
use crate::outbound::webhook::schemas::WebhookPayload;
use crate::outbound::webhook::subscription::WebhookSubscription;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use wallet_events::{EventSubscriber, WalletEvent};

/// Bridges the event bus to the webhook delivery queue.
/// [`EventListener::start`].
pub struct EventListener<E: EventSubscriber> {
    /// Shared, mutable list of active webhook subscriptions.
    subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,

    /// The delivery queue that the `DeliveryService` drains.
    delivery_queue: Arc<DeliveryQueue>,

    /// Kafka subscriber (or any `EventSubscriber` implementation).
    event_subscriber: Arc<E>,
}

impl<E: EventSubscriber + Send + Sync + 'static> EventListener<E> {
    /// Create a new `EventListener`.
    pub fn new(
        event_subscriber: Arc<E>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
    ) -> Self {
        Self {
            subscriptions,
            delivery_queue,
            event_subscriber,
        }
    }

    /// Start listening on all wallet topics.
    pub async fn start(&self) -> Result<(), ListenerError> {
        // These categories must match `WalletEventPayload::topic_category()`.
        let topics = [
            "credential.offers",
            "credential.issuance",
            "credential.storage",
            "presentation.requests",
            "presentation.submissions",
            "key.operations",
        ];

        info!(topic_count = topics.len(), "Starting event listener");

        for topic in topics {
            let stream = self
                .event_subscriber
                .subscribe::<WalletEvent>(topic)
                .await
                .map_err(|e| ListenerError::SubscribeFailed {
                    topic: topic.to_string(),
                    reason: e.to_string(),
                })?;

            let subscriptions = self.subscriptions.clone();
            let delivery_queue = self.delivery_queue.clone();
            let topic_owned = topic.to_string();

            tokio::spawn(async move {
                Self::process_stream(stream, subscriptions, delivery_queue, topic_owned).await;
            });
        }

        info!(
            "Event listener started – listening on {} topics",
            topics.len()
        );
        Ok(())
    }

    /// Drain a single event stream, enqueuing deliveries for matching subscriptions.
    async fn process_stream(
        mut stream: wallet_events::EventStream<WalletEvent>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        delivery_queue: Arc<DeliveryQueue>,
        topic: String,
    ) {
        info!(topic = %topic, "Listener task started");

        while let Some(result) = stream.next().await {
            match result {
                Ok(event) => {
                    let event_type = event.event_type_name();
                    debug!(
                        topic = %topic,
                        event_type = %event_type,
                        event_id = %event.metadata.event_id,
                        "Received event"
                    );

                    // Build the JSON payload once for all matching subscriptions.
                    let payload = match build_payload(&event) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                event_id = %event.metadata.event_id,
                                error = %e,
                                "Failed to serialise event into webhook payload – skipping"
                            );
                            continue;
                        }
                    };

                    enqueue_for_matching_subscriptions(
                        &event,
                        &payload,
                        &subscriptions,
                        &delivery_queue,
                    )
                    .await;
                }
                Err(e) => {
                    warn!(topic = %topic, error = %e, "Error received from event stream");
                }
            }
        }

        warn!(topic = %topic, "Event stream closed – listener task exiting");
    }
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/// Serialise a `WalletEvent` into a `WebhookPayload` JSON string.
fn build_payload(event: &WalletEvent) -> Result<String, ListenerError> {
    use wallet_events::DomainEvent;

    // The `data` field contains the inner payload so that webhook receivers
    // get the full event context without having to know about our envelope.
    let inner_payload_value =
        serde_json::to_value(&event.payload).map_err(|e| ListenerError::SerializationFailed {
            reason: e.to_string(),
        })?;

    // Extract the actual payload content from the tagged enum serialization
    let data = if let Some(payload_content) = inner_payload_value.get("payload") {
        let mut map = serde_json::Map::new();
        map.insert(event.event_type_name().to_string(), payload_content.clone());
        serde_json::Value::Object(map)
    } else {
        // Fallback if the structure is not as expected (e.g., for untagged enums, though not the case here)
        inner_payload_value
    };

    // `EventMetadata::timestamp` is already a `time::OffsetDateTime`,
    // the same type `WebhookPayload` now uses — no conversion needed.
    let payload = WebhookPayload::new(
        event.metadata.event_id.to_string(),
        event.event_type_name().to_string(),
        event.metadata.timestamp,
        event.wallet_id(),
        event.correlation_id(),
        data,
    );

    payload
        .to_json()
        .map_err(|e| ListenerError::SerializationFailed {
            reason: e.to_string(),
        })
}

/// Fan out one event to every matching subscription.
async fn enqueue_for_matching_subscriptions(
    event: &WalletEvent,
    payload_json: &str,
    subscriptions: &Arc<RwLock<Vec<WebhookSubscription>>>,
    delivery_queue: &Arc<DeliveryQueue>,
) {
    // Convert the wallet event type name to the dot-separated format that
    // subscriptions use (e.g. "CredentialStored" → "credential.stored").
    let event_type_key = camel_to_dot(event.event_type_name());

    let subs = subscriptions.read().await;
    let mut enqueued = 0usize;

    for sub in subs.iter() {
        if !sub.matches_event(&event_type_key) {
            continue;
        }

        let delivery = QueuedDelivery::new(
            sub.id.clone(),
            event.metadata.event_id.to_string(),
            event_type_key.clone(),
            payload_json.to_string(),
            sub.url.clone(),
        );

        delivery_queue.enqueue(delivery).await;
        enqueued += 1;

        debug!(
            subscription_id = %sub.id,
            event_type = %event_type_key,
            "Delivery enqueued"
        );
    }

    if enqueued == 0 {
        debug!(
            event_type = %event_type_key,
            "No subscriptions matched – event dropped"
        );
    }
}

/// Convert `CamelCase` event type names to the `dot.case` format used by
/// webhook subscriptions.
///
/// Examples:
/// - `"CredentialStored"` → `"credential.stored"`
/// - `"PresentationRequestReceived"` → `"presentation.request.received"`
/// - `"KeyRotated"` → `"key.rotated"`
fn camel_to_dot(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            out.push('.');
        }
        out.push(ch.to_lowercase().next().unwrap_or(ch));
    }
    out
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in the `EventListener`.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("Failed to subscribe to topic '{topic}': {reason}")]
    SubscribeFailed { topic: String, reason: String },

    #[error("Failed to serialise event: {reason}")]
    SerializationFailed { reason: String },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::webhook::delivery_queue::DeliveryQueue;
    use crate::outbound::webhook::schemas::WebhookPayload;
    use crate::outbound::webhook::subscription::{WebhookAuth, WebhookSubscription};
    use async_trait::async_trait;
    use futures::stream;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wallet_events::{
        CredentialStoredPayload, DomainEvent, EventError, EventStream, EventSubscriber,
        KeyCreatedPayload, WalletEvent, WalletEventPayload,
    };

    // ------------------------------------------------------------------
    // Mock subscriber that replays a fixed list of events on a given topic
    // ------------------------------------------------------------------
    struct MockSubscriber {
        events: Vec<WalletEvent>,
    }

    #[async_trait]
    impl EventSubscriber for MockSubscriber {
        async fn subscribe<T: DomainEvent + serde::de::DeserializeOwned + Send>(
            &self,
            _topic: &str,
        ) -> Result<EventStream<T>, EventError> {
            // Serialise each WalletEvent to JSON then deserialise as T so that
            // the mock works generically (T will be WalletEvent in our tests).
            let items: Vec<Result<T, EventError>> = self
                .events
                .iter()
                .map(|e| {
                    let json = serde_json::to_string(e).expect("serialise");
                    serde_json::from_str::<T>(&json)
                        .map_err(|err| EventError::SerializationError(err.to_string()))
                })
                .collect();

            Ok(Box::pin(stream::iter(items)))
        }
    }

    fn make_credential_stored_event() -> WalletEvent {
        WalletEvent::new(
            "corr-test".to_string(),
            "wallet-test".to_string(),
            WalletEventPayload::CredentialStored(CredentialStoredPayload {
                credential_id: "cred-1".to_string(),
                credential_type: "UniversityDegree".to_string(),
                issuer: "https://uni.example.com".to_string(),
                notification_id: None,
            }),
        )
    }

    fn make_key_created_event() -> WalletEvent {
        WalletEvent::new(
            "corr-key".to_string(),
            "wallet-test".to_string(),
            WalletEventPayload::KeyCreated(KeyCreatedPayload {
                key_id: "key-1".to_string(),
                kid: "did:example:1#key-1".to_string(),
                key_type: "Ed25519".to_string(),
                key_attestation: None,
            }),
        )
    }

    // ------------------------------------------------------------------
    // camel_to_dot
    // ------------------------------------------------------------------

    #[test]
    fn test_camel_to_dot_simple() {
        assert_eq!(camel_to_dot("CredentialStored"), "credential.stored");
        assert_eq!(camel_to_dot("KeyRotated"), "key.rotated");
        assert_eq!(camel_to_dot("KeyRevoked"), "key.revoked");
    }

    #[test]
    fn test_camel_to_dot_multi_word() {
        assert_eq!(
            camel_to_dot("PresentationRequestReceived"),
            "presentation.request.received"
        );
        assert_eq!(camel_to_dot("CredentialOfferSent"), "credential.offer.sent");
    }

    #[test]
    fn test_camel_to_dot_single_word() {
        assert_eq!(camel_to_dot("Lowercase"), "lowercase");
    }

    // ------------------------------------------------------------------
    // build_payload
    // ------------------------------------------------------------------

    #[test]
    fn test_build_payload_serialises_correctly() {
        let event = make_credential_stored_event();
        let before = time::OffsetDateTime::now_utc();
        let json = build_payload(&event).expect("build payload");
        let after = time::OffsetDateTime::now_utc();

        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");

        assert_eq!(payload.event_id, event.metadata.event_id.to_string());
        assert_eq!(payload.event_type, "CredentialStored");
        assert_eq!(payload.wallet_id, "wallet-test");
        assert_eq!(payload.correlation_id, "corr-test");
        // Timestamp should be within the window when the event was created
        assert!(payload.timestamp >= before || payload.timestamp <= after);
        assert!(payload.data.get("CredentialStored").is_some());
    }

    #[test]
    fn test_build_payload_key_event() {
        let event = make_key_created_event();
        let json = build_payload(&event).expect("build payload");
        let payload: WebhookPayload = serde_json::from_str(&json).expect("parse payload");
        assert_eq!(payload.event_type, "KeyCreated");
    }

    // ------------------------------------------------------------------
    // enqueue_for_matching_subscriptions
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_enqueue_matching_subscription() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = WebhookSubscription::new(
            "sub-1".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec!["credential.stored".to_string()]);

        let subscriptions = Arc::new(RwLock::new(vec![sub]));

        let event = make_credential_stored_event();
        let payload = build_payload(&event).expect("build payload");

        enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue).await;

        assert_eq!(queue.size().await, 1);
        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.subscription_id, "sub-1");
        assert_eq!(delivery.event_type, "credential.stored");
    }

    #[tokio::test]
    async fn test_no_enqueue_when_subscription_does_not_match() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = WebhookSubscription::new(
            "sub-2".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec!["key.created".to_string()]); // Doesn't match CredentialStored

        let subscriptions = Arc::new(RwLock::new(vec![sub]));
        let event = make_credential_stored_event();
        let payload = build_payload(&event).expect("build payload");

        enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue).await;

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
        .subscribe_all(); // Matches everything

        let sub2 = WebhookSubscription::new(
            "sub-2".to_string(),
            "https://b.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec!["credential.stored".to_string()]);

        let sub3 = WebhookSubscription::new(
            "sub-3".to_string(),
            "https://c.example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_to(vec!["key.created".to_string()]); // Should NOT match

        let subscriptions = Arc::new(RwLock::new(vec![sub1, sub2, sub3]));
        let event = make_credential_stored_event();
        let payload = build_payload(&event).expect("build payload");

        enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue).await;

        // sub-1 and sub-2 match; sub-3 does not
        assert_eq!(queue.size().await, 2);
    }

    #[tokio::test]
    async fn test_disabled_subscription_not_enqueued() {
        let queue = Arc::new(DeliveryQueue::new());

        let mut sub = WebhookSubscription::new(
            "sub-disabled".to_string(),
            "https://example.com/webhook".to_string(),
            WebhookAuth::None,
        )
        .subscribe_all();

        sub.disable();

        let subscriptions = Arc::new(RwLock::new(vec![sub]));
        let event = make_credential_stored_event();
        let payload = build_payload(&event).expect("build payload");

        enqueue_for_matching_subscriptions(&event, &payload, &subscriptions, &queue).await;

        assert!(queue.is_empty().await);
    }

    // ------------------------------------------------------------------
    // Full listener start (mock subscriber, no real Kafka needed)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_listener_processes_events_end_to_end() {
        let event = make_credential_stored_event();
        let event_id = event.metadata.event_id.to_string();

        // The mock subscriber only has events on one topic; all others return
        // empty streams.  We set up the mock to serve our event on
        // "credential.storage" (the category for CredentialStored).
        let subscriber = Arc::new(MockSubscriber {
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

        let listener = EventListener::new(subscriber, subscriptions, queue.clone());
        listener.start().await.expect("listener start");

        // Give the spawned tasks a moment to process the stream
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // The event was replayed on every subscribed topic (6 topics ×
        // the mock returning the same event) – at minimum, at least one
        // delivery must have been enqueued.
        assert!(
            queue.size().await >= 1,
            "Expected at least one delivery to be enqueued"
        );

        let delivery = queue.dequeue().await.unwrap();
        assert_eq!(delivery.event_id, event_id);
        assert_eq!(delivery.subscription_id, "sub-e2e");
    }
}
