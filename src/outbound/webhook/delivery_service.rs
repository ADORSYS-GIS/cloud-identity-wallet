use crate::outbound::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
use crate::outbound::webhook::http_client::{HttpClientError, WebhookHttpClient};
use crate::outbound::webhook::retry_strategy::RetryStrategy;
use crate::outbound::webhook::schemas::DeliveryStatus;
use crate::outbound::webhook::subscription::WebhookSubscription;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Drains the delivery queue and sends webhooks with retry logic.
///
/// `DeliveryService` is designed to run as a long-lived background task.
/// Call [`DeliveryService::start`] to launch the processing loop inside a
/// `tokio::spawn`.
///
/// Responsibilities:
/// 1. Dequeue deliveries produced by the [`EventListener`].
/// 2. Look up the matching `WebhookSubscription` for its URL and auth config.
/// 3. Call the endpoint with [`WebhookHttpClient`].
/// 4. On failure, consult the [`RetryStrategy`] and either re-enqueue or
///    record a permanent failure.
/// 5. Record all attempt outcomes in `DeliveryQueue::record_status`.
pub struct DeliveryService {
    /// Shared delivery queue – same instance as the `EventListener` writes to.
    delivery_queue: Arc<DeliveryQueue>,

    /// Shared, mutable subscription list.
    subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,

    /// HTTP client reused across all requests.
    http_client: Arc<WebhookHttpClient>,

    /// Retry configuration applied to every delivery.
    retry_strategy: RetryStrategy,
}

impl DeliveryService {
    /// Create a `DeliveryService` with the default retry strategy.
    pub fn new(
        delivery_queue: Arc<DeliveryQueue>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
    ) -> Result<Self, DeliveryServiceError> {
        let http_client = WebhookHttpClient::new()
            .map_err(|e| DeliveryServiceError::Initialisation(e.to_string()))?;

        Ok(Self {
            delivery_queue,
            subscriptions,
            http_client: Arc::new(http_client),
            retry_strategy: RetryStrategy::default_strategy(),
        })
    }

    /// Override the retry strategy.
    pub fn with_retry_strategy(mut self, strategy: RetryStrategy) -> Self {
        self.retry_strategy = strategy;
        self
    }

    /// Start the processing loop.
    ///
    /// Returns immediately; the actual work happens inside a `tokio::spawn`.
    /// The spawned task runs until the process exits.
    pub fn start(self: Arc<Self>) {
        info!("Webhook delivery service starting");

        let service = self.clone();
        tokio::spawn(async move {
            service.run_loop().await;
        });
    }

    /// Inner processing loop – poll the queue and dispatch deliveries.
    async fn run_loop(&self) {
        loop {
            match self.delivery_queue.dequeue().await {
                Some(delivery) => {
                    let queue = self.delivery_queue.clone();
                    let subscriptions = self.subscriptions.clone();
                    let http_client = self.http_client.clone();
                    let retry_strategy = self.retry_strategy.clone();

                    tokio::spawn(async move {
                        Self::process_delivery(
                            delivery,
                            queue,
                            subscriptions,
                            http_client,
                            retry_strategy,
                        )
                        .await;
                    });
                }
                None => {
                    // Queue is empty; back off briefly before polling again.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Process a single delivery attempt.
    ///
    /// Looks up the subscription, sends the HTTP request, records the status,
    /// and re-enqueues on retryable failure.
    async fn process_delivery(
        delivery: QueuedDelivery,
        queue: Arc<DeliveryQueue>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        http_client: Arc<WebhookHttpClient>,
        retry_strategy: RetryStrategy,
    ) {
        let attempt = delivery.attempt;
        let sub_id = &delivery.subscription_id;
        let event_id = &delivery.event_id;

        debug!(
            subscription_id = %sub_id,
            event_id = %event_id,
            attempt = attempt,
            "Processing delivery"
        );

        // Look up the subscription to get auth details.
        let auth = {
            let subs = subscriptions.read().await;
            subs.iter()
                .find(|s| s.id == *sub_id)
                .map(|s| s.auth.clone())
        };

        let auth = match auth {
            Some(a) => a,
            None => {
                // Subscription was removed between enqueue and delivery.
                warn!(
                    subscription_id = %sub_id,
                    "Subscription not found – dropping delivery"
                );
                let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                    .permanent_failure("Subscription removed".to_string());
                queue.record_status(status).await;
                return;
            }
        };

        // Record that the attempt has started.
        let in_progress =
            DeliveryStatus::pending(sub_id.clone(), event_id.clone()).in_progress(attempt + 1);
        queue.record_status(in_progress).await;

        // Send the HTTP POST.
        let result = http_client
            .send_webhook(&delivery.url, &delivery.payload, &auth)
            .await;

        match result {
            Ok((status_code, response_time_ms, _body)) => {
                info!(
                    subscription_id = %sub_id,
                    event_id = %event_id,
                    attempt = attempt + 1,
                    status_code = status_code,
                    response_time_ms = response_time_ms,
                    "Webhook delivered successfully"
                );

                let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                    .succeeded(status_code, response_time_ms);
                queue.record_status(status).await;
            }
            Err(e) => {
                let status_code = extract_status_code(&e);

                // Decide whether to retry.
                let should_retry = match status_code {
                    Some(code) => retry_strategy.should_retry_status(code),
                    None => retry_strategy.should_retry(attempt), // Network errors always retry
                };

                if should_retry && retry_strategy.should_retry(attempt) {
                    // Calculate next retry delay.
                    let delay = retry_strategy.next_delay(attempt + 1);
                    let next_retry_at = delay.map(|d| time::OffsetDateTime::now_utc() + d);

                    warn!(
                        subscription_id = %sub_id,
                        event_id = %event_id,
                        attempt = attempt + 1,
                        max_attempts = retry_strategy.max_attempts(),
                        error = %e,
                        "Webhook delivery failed – will retry"
                    );

                    let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone()).failed(
                        status_code,
                        e.to_string(),
                        next_retry_at,
                    );
                    queue.record_status(status).await;

                    // Wait then re-enqueue.
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    queue.requeue(delivery).await;
                } else {
                    error!(
                        subscription_id = %sub_id,
                        event_id = %event_id,
                        attempt = attempt + 1,
                        error = %e,
                        "Webhook delivery permanently failed"
                    );

                    let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                        .permanent_failure(format!("Failed after {} attempt(s): {e}", attempt + 1));
                    queue.record_status(status).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract an HTTP status code from a `HttpClientError`, if available.
fn extract_status_code(err: &HttpClientError) -> Option<u16> {
    match err {
        HttpClientError::ResponseError { status, .. } => Some(status.as_u16()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during `DeliveryService` initialisation.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryServiceError {
    #[error("Initialisation failed: {0}")]
    Initialisation(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
    use crate::outbound::webhook::retry_strategy::RetryStrategy;
    use crate::outbound::webhook::schemas::DeliveryState;
    use crate::outbound::webhook::subscription::{WebhookAuth, WebhookSubscription};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    // Helper: build a simple subscription
    fn make_sub(id: &str, url: &str) -> WebhookSubscription {
        WebhookSubscription::new(id.to_string(), url.to_string(), WebhookAuth::None).subscribe_all()
    }

    // Helper: build a basic queued delivery
    fn make_delivery(sub_id: &str, event_id: &str, url: &str) -> QueuedDelivery {
        QueuedDelivery::new(
            sub_id.to_string(),
            event_id.to_string(),
            "credential.stored".to_string(),
            r#"{"event_type":"credential.stored"}"#.to_string(),
            url.to_string(),
        )
    }

    // ------------------------------------------------------------------
    // Initialisation
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_service_creation() {
        let queue = Arc::new(DeliveryQueue::new());
        let subs = Arc::new(RwLock::new(vec![]));
        let service = DeliveryService::new(queue, subs);
        assert!(service.is_ok());
    }

    // ------------------------------------------------------------------
    // Subscription lookup
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_delivery_dropped_when_subscription_removed() {
        let queue = Arc::new(DeliveryQueue::new());
        // No subscriptions registered
        let subs = Arc::new(RwLock::new(vec![]));

        let delivery = make_delivery("sub-gone", "evt-1", "https://example.com");

        DeliveryService::process_delivery(
            delivery,
            queue.clone(),
            subs,
            Arc::new(WebhookHttpClient::new().unwrap()),
            RetryStrategy::default_strategy(),
        )
        .await;

        // Should record a permanent failure and nothing re-queued
        assert!(queue.is_empty().await);
        let status = queue
            .get_latest_status("sub-gone", "evt-1")
            .await
            .expect("status should be recorded");
        assert_eq!(status.status, DeliveryState::PermanentFailure);
        assert!(status.error.unwrap().contains("Subscription removed"));
    }

    // ------------------------------------------------------------------
    // Retry behaviour – unreachable endpoint
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_failed_delivery_is_requeued() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = make_sub("sub-retry", "http://127.0.0.1:19999"); // Nothing listening here
        let subs = Arc::new(RwLock::new(vec![sub]));

        // Use a strategy with 3 max attempts so the first failure re-queues
        let strategy = RetryStrategy::new(3, 1); // 1 ms base delay

        let delivery = make_delivery("sub-retry", "evt-retry", "http://127.0.0.1:19999");

        DeliveryService::process_delivery(
            delivery,
            queue.clone(),
            subs.clone(),
            Arc::new(WebhookHttpClient::new().unwrap()),
            strategy,
        )
        .await;

        // Delivery should have been re-queued (attempt 0 → attempt 1)
        assert_eq!(queue.size().await, 1);
        let requeued = queue.dequeue().await.unwrap();
        assert_eq!(requeued.attempt, 1);

        // Status should be Failed (not Permanent)
        let status = queue
            .get_latest_status("sub-retry", "evt-retry")
            .await
            .expect("status should exist");
        assert_eq!(status.status, DeliveryState::Failed);
    }

    #[tokio::test]
    async fn test_permanently_fails_after_max_attempts() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = make_sub("sub-perm", "http://127.0.0.1:19998");
        let subs = Arc::new(RwLock::new(vec![sub]));

        // Strategy with 1 max attempt – no retries
        let strategy = RetryStrategy::new(1, 1);

        let delivery = make_delivery("sub-perm", "evt-perm", "http://127.0.0.1:19998");

        DeliveryService::process_delivery(
            delivery,
            queue.clone(),
            subs,
            Arc::new(WebhookHttpClient::new().unwrap()),
            strategy,
        )
        .await;

        // Nothing should be re-queued
        assert!(queue.is_empty().await);

        let status = queue
            .get_latest_status("sub-perm", "evt-perm")
            .await
            .expect("status recorded");
        assert_eq!(status.status, DeliveryState::PermanentFailure);
    }

    // ------------------------------------------------------------------
    // extract_status_code
    // ------------------------------------------------------------------

    #[test]
    fn test_extract_status_code_response_error() {
        let err = HttpClientError::ResponseError {
            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            body: "oops".to_string(),
        };
        assert_eq!(extract_status_code(&err), Some(500));
    }

    #[test]
    fn test_extract_status_code_network_error() {
        let err = HttpClientError::NetworkError("timeout".to_string());
        assert_eq!(extract_status_code(&err), None);
    }

    #[test]
    fn test_extract_status_code_timeout() {
        let err = HttpClientError::Timeout(std::time::Duration::from_secs(30));
        assert_eq!(extract_status_code(&err), None);
    }
}
