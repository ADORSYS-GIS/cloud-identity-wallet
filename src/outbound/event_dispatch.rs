use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use redis::{AsyncCommands, PushKind, aio::ConnectionManager};
use tokio::sync::{broadcast, mpsc::UnboundedReceiver};
use tracing::warn;

use crate::domain::models::issuance::{IssuanceError, IssuanceEvent};
use crate::domain::ports::{IssuanceEventPublisher, IssuanceEventStream, IssuanceEventSubscriber};

/// Redis-backed event publisher.
#[derive(Debug, Clone)]
pub struct RedisEventPublisher {
    conn: ConnectionManager,
}

impl RedisEventPublisher {
    /// Create a new publisher backed by the given Redis connection.
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl IssuanceEventPublisher for RedisEventPublisher {
    async fn publish(&self, event: &IssuanceEvent) -> Result<(), IssuanceError> {
        let channel = format!("issuance:events:{}", event.session_id());
        let json = event.to_json()?;
        let mut conn = self.conn.clone();
        let _: () = conn.publish(&channel, &json).await.map_err(map_redis_err)?;
        Ok(())
    }
}

type Dispatcher = DashMap<String, broadcast::Sender<IssuanceEvent>>;

/// Redis-backed event subscriber.
///
/// The returned stream after subscription auto-terminates on `completed` or `failed` events.
#[derive(Debug, Clone)]
pub struct RedisEventSubscriber {
    conn: ConnectionManager,
    dispatcher: Arc<Dispatcher>,
}

impl RedisEventSubscriber {
    /// Build with an already-configured [RESP3] `ConnectionManager`.
    ///
    /// The `ConnectionManagerConfig` must have `set_push_sender` set before
    /// the manager is created, otherwise push messages will not be received.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// use cloud_identity_wallet::outbound::RedisEventSubscriber;
    /// use redis::{Client, aio::ConnectionManagerConfig};
    ///
    /// let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    /// let config = ConnectionManagerConfig::new().set_push_sender(tx);
    /// let client = Client::open("redis://127.0.0.1/?protocol=resp3")?;
    /// let conn = client.get_connection_manager_with_config(config).await?;
    ///
    /// let _subscriber = RedisEventSubscriber::new(conn, rx);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [RESP3]: https://github.com/redis/redis-specifications/blob/master/protocol/RESP3.md
    pub fn new(conn: ConnectionManager, push_rx: UnboundedReceiver<redis::PushInfo>) -> Self {
        let dispatcher = Arc::new(DashMap::new());
        Self::spawn_router(dispatcher.clone(), push_rx);
        Self { conn, dispatcher }
    }

    fn spawn_router(dispatcher: Arc<Dispatcher>, mut push_rx: UnboundedReceiver<redis::PushInfo>) {
        tokio::spawn(async move {
            while let Some(mut push) = push_rx.recv().await {
                if !matches!(push.kind, PushKind::Message | PushKind::SMessage) {
                    continue;
                }
                // data[0] = channel name, data[1] = payload
                if push.data.len() < 2 {
                    continue;
                }

                let data = std::mem::take(&mut push.data[1]);
                let payload: Vec<u8> = match redis::from_redis_value(data) {
                    Ok(value) => value,
                    Err(err) => {
                        warn!("failed to decode push payload: {err}");
                        continue;
                    }
                };
                let event = match IssuanceEvent::from_json(&payload) {
                    Ok(event) => event,
                    Err(err) => {
                        warn!("failed to deserialize IssuanceEvent: {err}");
                        continue;
                    }
                };

                let session_id = event.session_id().to_owned();
                let terminal = event.is_terminal();

                if let Some(tx) = dispatcher.get(&*session_id) {
                    let _ = tx.send(event);
                } else {
                    warn!(session_id = %session_id, "received event for unknown session");
                }

                // Remove after the terminal event is broadcast.
                if terminal {
                    dispatcher.remove(&*session_id);
                }
            }
        });
    }

    pub async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream, IssuanceError> {
        let channel = format!("issuance:events:{session_id}");
        let rx = self
            .dispatcher
            .entry(session_id.to_owned())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(32);
                tx
            })
            .subscribe();

        let mut conn = self.conn.clone();
        conn.subscribe(channel).await.map_err(map_redis_err)?;
        Ok(self.build_stream(session_id.to_owned(), rx, conn))
    }

    fn build_stream(
        &self,
        session_id: String,
        mut rx: broadcast::Receiver<IssuanceEvent>,
        mut conn: ConnectionManager,
    ) -> IssuanceEventStream {
        Box::pin(async_stream::stream! {
            let channel = format!("issuance:events:{session_id}");

            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let terminal = event.is_terminal();
                        yield event;
                        if terminal { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                    }
                }

            // Always UNSUBSCRIBE when the stream ends, regardless of reason.
            // Prevents accumulation of dead subscriptions on the server.
            if let Err(e) = conn.unsubscribe(channel).await {
                warn!(session_id = %session_id, "UNSUBSCRIBE failed: {e}");
            }
        })
    }
}

#[async_trait]
impl IssuanceEventSubscriber for RedisEventSubscriber {
    async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream, IssuanceError> {
        self.subscribe(session_id).await
    }
}

/// Maps a `redis::RedisError` into an `IssuanceError`.
fn map_redis_err(err: redis::RedisError) -> IssuanceError {
    IssuanceError::internal(err)
}

/// In-process event publisher.
///
/// Events are broadcast to all subscribers on the same channel.
/// Suitable for single-instance deployments and testing.
#[derive(Debug, Clone)]
pub struct MemoryEventPublisher {
    tx: broadcast::Sender<IssuanceEvent>,
}

impl MemoryEventPublisher {
    /// Create a new publisher with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Create a publisher from an existing broadcast sender.
    ///
    /// Use this to share the channel with a [`MemoryEventSubscriber`].
    pub fn from_sender(tx: broadcast::Sender<IssuanceEvent>) -> Self {
        Self { tx }
    }

    /// Returns the underlying sender for sharing with a subscriber.
    pub fn sender(&self) -> &broadcast::Sender<IssuanceEvent> {
        &self.tx
    }
}

#[async_trait]
impl IssuanceEventPublisher for MemoryEventPublisher {
    async fn publish(&self, event: &IssuanceEvent) -> Result<(), IssuanceError> {
        let _ = self.tx.send(event.clone());
        Ok(())
    }
}

/// In-process event subscriber backed by `tokio::sync::broadcast`.
///
/// Subscribes to the shared broadcast channel and filters events by
/// session ID. Auto-terminates on terminal events.
#[derive(Debug, Clone)]
pub struct MemoryEventSubscriber {
    tx: broadcast::Sender<IssuanceEvent>,
}

impl MemoryEventSubscriber {
    /// Create a new subscriber sharing the channel with the given publisher.
    pub fn new(publisher: &MemoryEventPublisher) -> Self {
        Self {
            tx: publisher.sender().clone(),
        }
    }

    /// Create a subscriber from an existing broadcast sender.
    pub fn from_sender(tx: broadcast::Sender<IssuanceEvent>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl IssuanceEventSubscriber for MemoryEventSubscriber {
    async fn subscribe(&self, session_id: &str) -> Result<IssuanceEventStream, IssuanceError> {
        let mut rx = self.tx.subscribe();
        let session_id = session_id.to_owned();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        // Only yield events for the requested session
                        if event.session_id() != session_id {
                            continue;
                        }
                        let is_terminal = event.is_terminal();
                        yield event;
                        if is_terminal {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(n, "SSE subscriber lagged, dropping events");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::models::issuance::{ProcessingStep, SseCompletedEvent, SseProcessingEvent};
    use futures::StreamExt;

    #[tokio::test]
    async fn memory_publish_subscribe_round_trip() {
        let publisher = MemoryEventPublisher::new(16);
        let subscriber = MemoryEventSubscriber::new(&publisher);

        let mut stream = subscriber.subscribe("ses_1").await.unwrap();

        // Publish events
        let processing = IssuanceEvent::Processing(SseProcessingEvent::new(
            "ses_1",
            ProcessingStep::ExchangingToken,
        ));
        let completed = IssuanceEvent::Completed(SseCompletedEvent::new(
            "ses_1",
            vec!["id1".into()],
            vec!["type1".into()],
        ));

        publisher.publish(&processing).await.unwrap();
        publisher.publish(&completed).await.unwrap();

        // Read events from stream
        let e1 = stream.next().await.unwrap();
        assert!(matches!(e1, IssuanceEvent::Processing(_)));

        let e2 = stream.next().await.unwrap();
        assert!(matches!(e2, IssuanceEvent::Completed(_)));

        // Stream should terminate after terminal event
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn memory_subscriber_filters_by_session() {
        let publisher = MemoryEventPublisher::new(16);
        let subscriber = MemoryEventSubscriber::new(&publisher);

        let mut stream = subscriber.subscribe("ses_1").await.unwrap();

        // Publish event for a different session
        let other = IssuanceEvent::Processing(SseProcessingEvent::new(
            "ses_OTHER",
            ProcessingStep::ExchangingToken,
        ));
        publisher.publish(&other).await.unwrap();

        // Publish terminal event for our session
        let completed = IssuanceEvent::Completed(SseCompletedEvent::new("ses_1", vec![], vec![]));
        publisher.publish(&completed).await.unwrap();

        // Should only receive the completed event (not the other session's event)
        let e1 = stream.next().await.unwrap();
        assert!(matches!(e1, IssuanceEvent::Completed(_)));
        assert_eq!(e1.session_id(), "ses_1");
    }
}
