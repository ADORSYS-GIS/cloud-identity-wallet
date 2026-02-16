// Webhook delivery module
//
// This module contains independent components for webhook delivery
// that do not depend on the event bus (Ticket 1).
//
// Components that depend on Ticket 1 (event_listener, delivery_service)
// will be added after the event bus is merged.

pub mod delivery_queue;
pub mod hmac_signer;
pub mod http_client;
pub mod retry_strategy;
pub mod schemas;
pub mod subscription;

// Re-export commonly used types
pub use delivery_queue::{DeliveryQueue, QueuedDelivery};
pub use hmac_signer::{HmacSigner, format_signature_header, parse_signature_header};
pub use http_client::{HttpClientError, WebhookHttpClient};
pub use retry_strategy::RetryStrategy;
pub use schemas::{DeliveryState, DeliveryStatus, WebhookPayload, WebhookResponse};
pub use subscription::{WebhookAuth, WebhookSubscription};
