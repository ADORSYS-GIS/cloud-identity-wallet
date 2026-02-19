// Webhook delivery module
//
// Independent components (no dependency on wallet-events):
//   delivery_queue, hmac_signer, http_client, retry_strategy, schemas, subscription
//
// Integration components (depend on wallet-events / Ticket 1):
//   event_listener  – subscribes to the event bus and enqueues deliveries
//   delivery_service – drains the queue and sends HTTP webhooks

pub mod delivery_queue;
pub mod delivery_service;
pub mod event_listener;
pub mod hmac_signer;
pub mod http_client;
pub mod retry_strategy;
pub mod schemas;
pub mod subscription;

// Re-export commonly used types
pub use delivery_queue::{DeliveryQueue, QueuedDelivery};
pub use delivery_service::{DeliveryService, DeliveryServiceError};
pub use event_listener::{EventListener, ListenerError};
pub use hmac_signer::{HmacSigner, format_signature_header, parse_signature_header};
pub use http_client::{HttpClientError, WebhookHttpClient};
pub use retry_strategy::RetryStrategy;
pub use schemas::{DeliveryState, DeliveryStatus, WebhookPayload, WebhookResponse};
pub use subscription::{WebhookAuth, WebhookSubscription};
