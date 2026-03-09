use crate::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
use crate::webhook::http_client::{HttpClientError, WebhookHttpClient};
use crate::webhook::retry_strategy::RetryStrategy;
use crate::webhook::schemas::DeliveryStatus;
use crate::webhook::subscription::WebhookSubscription;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

/// Maximum number of webhook deliveries that may be in-flight concurrently.
const MAX_CONCURRENT_DELIVERIES: usize = 64;

/// Background service that drains the [`DeliveryQueue`] and sends webhooks.
///
/// `DeliveryService` runs a single long-lived loop (started via [`Self::start`])
/// that pops [`QueuedDelivery`] items from the queue and spawns a Tokio task for
/// each one. Concurrency is bounded by an internal [`Semaphore`] capped at
/// [`MAX_CONCURRENT_DELIVERIES`] so the service cannot exhaust system resources
/// under burst load.
///
/// Each delivery task:
/// 1. Looks up the matching [`WebhookSubscription`] to obtain auth credentials.
/// 2. POSTs the payload to the subscription URL via [`WebhookHttpClient`].
/// 3. On success, records a [`DeliveryState::Succeeded`] status.
/// 4. On failure, checks [`RetryStrategy`] and either requeues with backoff or
///    records a [`DeliveryState::PermanentFailure`] status.
pub struct DeliveryService {
    delivery_queue: Arc<DeliveryQueue>,

    subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,

    http_client: Arc<WebhookHttpClient>,

    retry_strategy: RetryStrategy,

    /// Limits the number of concurrent in-flight delivery tasks.
    semaphore: Arc<Semaphore>,
}

impl DeliveryService {
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
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        })
    }

    /// Override the retry strategy.
    pub fn with_retry_strategy(mut self, strategy: RetryStrategy) -> Self {
        self.retry_strategy = strategy;
        self
    }

    /// Start the processing loop.
    pub fn start(self: Arc<Self>) {
        let service = self.clone();
        tokio::spawn(async move {
            service.run_loop().await;
        });
    }

    async fn run_loop(&self) {
        loop {
            match self.delivery_queue.dequeue().await {
                Some(delivery) => {
                    let queue = self.delivery_queue.clone();
                    let subscriptions = self.subscriptions.clone();
                    let http_client = self.http_client.clone();
                    let retry_strategy = self.retry_strategy.clone();
                    let semaphore = self.semaphore.clone();

                    tokio::spawn(async move {
                        // Acquire a permit before doing any work. The permit is held
                        // for the lifetime of the task and released on drop, ensuring
                        // at most MAX_CONCURRENT_DELIVERIES tasks run at once.
                        let _permit = semaphore
                            .acquire_owned()
                            .await
                            .expect("semaphore should never be closed");

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
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Process a single delivery attempt.
    pub(crate) async fn process_delivery(
        delivery: QueuedDelivery,
        queue: Arc<DeliveryQueue>,
        subscriptions: Arc<RwLock<Vec<WebhookSubscription>>>,
        http_client: Arc<WebhookHttpClient>,
        retry_strategy: RetryStrategy,
    ) {
        let attempt = delivery.attempt;
        let sub_id = &delivery.subscription_id;
        let event_id = &delivery.event_id;

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
                let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                    .permanent_failure("Subscription removed".to_string());
                queue.record_status(status).await;
                return;
            }
        };

        let in_progress =
            DeliveryStatus::pending(sub_id.clone(), event_id.clone()).in_progress(attempt + 1);
        queue.record_status(in_progress).await;

        let result = http_client
            .send_webhook(&delivery.url, &delivery.payload, &auth)
            .await;

        match result {
            Ok((status_code, response_time_ms, _body)) => {
                let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                    .succeeded(status_code, response_time_ms);
                queue.record_status(status).await;
            }
            Err(e) => {
                let status_code = extract_status_code(&e);

                if retry_strategy.should_retry(attempt) {
                    let delay = retry_strategy.next_delay(attempt + 1);
                    let next_retry_at = delay.map(|d| time::OffsetDateTime::now_utc() + d);

                    let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone()).failed(
                        status_code,
                        e.to_string(),
                        next_retry_at,
                    );
                    queue.record_status(status).await;

                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    queue.requeue(delivery).await;
                } else {
                    let status = DeliveryStatus::pending(sub_id.clone(), event_id.clone())
                        .permanent_failure(format!("Failed after {} attempt(s): {e}", attempt + 1));
                    queue.record_status(status).await;
                }
            }
        }
    }
}

fn extract_status_code(err: &HttpClientError) -> Option<u16> {
    match err {
        HttpClientError::ResponseError { status, .. } => Some(status.as_u16()),
        _ => None,
    }
}

/// Errors that can occur during `DeliveryService` initialisation.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryServiceError {
    #[error("Initialisation failed: {0}")]
    Initialisation(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::delivery_queue::{DeliveryQueue, QueuedDelivery};
    use crate::webhook::http_client::HttpClientError;
    use crate::webhook::retry_strategy::RetryStrategy;
    use crate::webhook::schemas::DeliveryState;
    use crate::webhook::subscription::{WebhookAuth, WebhookSubscription};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_sub(id: &str, url: &str) -> WebhookSubscription {
        WebhookSubscription::new(id.to_string(), url.to_string(), WebhookAuth::None).subscribe_all()
    }

    fn make_delivery(sub_id: &str, event_id: &str, url: &str) -> QueuedDelivery {
        QueuedDelivery::new(
            sub_id.to_string(),
            event_id.to_string(),
            "credential.stored".to_string(),
            r#"{"event_type":"credential.stored"}"#.to_string(),
            url.to_string(),
        )
    }

    #[tokio::test]
    async fn test_semaphore_limits_concurrency() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES));
        assert_eq!(semaphore.available_permits(), MAX_CONCURRENT_DELIVERIES);

        // Acquire one permit — available count should drop by one.
        let _permit = semaphore.clone().acquire_owned().await.unwrap();
        assert_eq!(semaphore.available_permits(), MAX_CONCURRENT_DELIVERIES - 1);

        // Dropping the permit returns it.
        drop(_permit);
        assert_eq!(semaphore.available_permits(), MAX_CONCURRENT_DELIVERIES);
    }

    #[tokio::test]
    async fn test_service_creation() {
        let queue = Arc::new(DeliveryQueue::new());
        let subs = Arc::new(RwLock::new(vec![]));
        let service = DeliveryService::new(queue, subs);
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_delivery_dropped_when_subscription_removed() {
        let queue = Arc::new(DeliveryQueue::new());
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

        assert!(queue.is_empty().await);
        let status = queue
            .get_latest_status("sub-gone", "evt-1")
            .await
            .expect("status should be recorded");
        assert_eq!(status.status, DeliveryState::PermanentFailure);
        assert!(status.error.unwrap().contains("Subscription removed"));
    }

    #[tokio::test]
    async fn test_failed_delivery_is_requeued() {
        let queue = Arc::new(DeliveryQueue::new());
        let sub = make_sub("sub-retry", "http://127.0.0.1:19999");
        let subs = Arc::new(RwLock::new(vec![sub]));

        let strategy = RetryStrategy::new(3, 1);
        let delivery = make_delivery("sub-retry", "evt-retry", "http://127.0.0.1:19999");

        DeliveryService::process_delivery(
            delivery,
            queue.clone(),
            subs,
            Arc::new(WebhookHttpClient::new().unwrap()),
            strategy,
        )
        .await;

        assert_eq!(queue.size().await, 1);
        let requeued = queue.dequeue().await.unwrap();
        assert_eq!(requeued.attempt, 1);

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

        assert!(queue.is_empty().await);

        let status = queue
            .get_latest_status("sub-perm", "evt-perm")
            .await
            .expect("status recorded");
        assert_eq!(status.status, DeliveryState::PermanentFailure);
    }

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
