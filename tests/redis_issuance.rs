//! Integration tests for Redis-backed issuance infrastructure.
//!
//! Tests cover:
//! - `RedisTaskQueue`: push/pop/ack, FIFO ordering, stale reclaim, concurrent consumers
//! - `RedisEventPublisher` + `RedisEventSubscriber`: pub/sub round-trip, terminal events,
//!   session filtering, late subscription

use std::time::Duration;

use cloud_identity_wallet::domain::models::issuance::{
    IssuanceEvent, ProcessingStep, SseCompletedEvent, SseFailedEvent, SseProcessingEvent,
};
use cloud_identity_wallet::domain::models::issuance::{IssuanceStep, IssuanceTask};
use cloud_identity_wallet::domain::ports::{IssuanceEventPublisher, IssuanceTaskQueue};
use cloud_identity_wallet::outbound::{RedisEventPublisher, RedisEventSubscriber, RedisTaskQueue};
use cloud_identity_wallet::session::FlowType;
use futures::StreamExt;
use redis::aio::ConnectionManagerConfig;
use redis::{Client as RedisClient, aio::ConnectionManager};
use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tokio::sync::mpsc::UnboundedReceiver;
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────────────

const REDIS_TAG: &str = "8-alpine";

/// Start a Redis container and return a plain connection manager (no push channel).
async fn init_redis() -> (ConnectionManager, ContainerAsync<Redis>) {
    let container = Redis::default()
        .with_tag(REDIS_TAG)
        .start()
        .await
        .expect("redis container failed to start");

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
    let url = format!("redis://{host}:{port}");

    let client = RedisClient::open(url).expect("failed to create redis client");
    let conn = client
        .get_connection_manager()
        .await
        .expect("failed to get redis connection manager");

    (conn, container)
}

/// Start a Redis container and return a RESP3 connection manager with push channel.
async fn init_redis_resp3() -> (
    ConnectionManager,
    UnboundedReceiver<redis::PushInfo>,
    ContainerAsync<Redis>,
) {
    let container = Redis::default()
        .with_tag(REDIS_TAG)
        .start()
        .await
        .expect("redis container failed to start");

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
    let url = format!("redis://{host}:{port}?protocol=resp3");

    let client = RedisClient::open(url).expect("failed to create redis client");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let config = ConnectionManagerConfig::new()
        .set_push_sender(tx)
        .set_automatic_resubscription();

    let conn = client
        .get_connection_manager_with_config(config)
        .await
        .expect("failed to get RESP3 connection manager");

    (conn, rx, container)
}

fn make_task(session_id: &str) -> IssuanceTask {
    IssuanceTask {
        queue_id: None,
        session_id: session_id.to_owned(),
        tenant_id: Uuid::new_v4(),
        flow: FlowType::PreAuthorizedCode,
        authorization_code: None,
        pkce_verifier: None,
        pre_authorized_code: Some("pre_code_123".into()),
        tx_code: None,
    }
}

// ── RedisTaskQueue ───────────────────────────────────────────────────────────

#[tokio::test]
async fn task_queue_push_pop_round_trip() {
    let (conn, _container) = init_redis().await;
    let queue = RedisTaskQueue::new(conn);

    let task = make_task("ses_round_trip");
    queue.push(&task).await.unwrap();

    let popped = queue
        .pop()
        .await
        .unwrap()
        .expect("queue should not be empty");
    assert_eq!(popped.session_id, "ses_round_trip");
    assert_eq!(popped.flow, FlowType::PreAuthorizedCode);
    assert_eq!(popped.pre_authorized_code.as_deref(), Some("pre_code_123"));
    assert!(popped.queue_id.is_some(), "queue_id must be set after pop");
}

#[tokio::test]
async fn task_queue_pop_returns_none_on_empty() {
    let (conn, _container) = init_redis().await;
    let queue = RedisTaskQueue::new(conn);

    let result = queue.pop().await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn task_queue_ack_removes_from_pending() {
    let (conn, _container) = init_redis().await;
    let queue = RedisTaskQueue::new(conn);

    let task = make_task("ses_ack");
    queue.push(&task).await.unwrap();

    let popped = queue.pop().await.unwrap().unwrap();
    queue.ack(&popped).await.unwrap();

    // After ack, nothing should be available (no stale reclaim either)
    let result = queue.pop().await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn task_queue_fifo_ordering() {
    let (conn, _container) = init_redis().await;
    let queue = RedisTaskQueue::new(conn);

    let t1 = make_task("ses_fifo_1");
    let t2 = make_task("ses_fifo_2");
    let t3 = make_task("ses_fifo_3");

    queue.push(&t1).await.unwrap();
    queue.push(&t2).await.unwrap();
    queue.push(&t3).await.unwrap();

    let p1 = queue.pop().await.unwrap().unwrap();
    assert_eq!(p1.session_id, "ses_fifo_1");
    queue.ack(&p1).await.unwrap();

    let p2 = queue.pop().await.unwrap().unwrap();
    assert_eq!(p2.session_id, "ses_fifo_2");
    queue.ack(&p2).await.unwrap();

    let p3 = queue.pop().await.unwrap().unwrap();
    assert_eq!(p3.session_id, "ses_fifo_3");
    queue.ack(&p3).await.unwrap();

    assert!(queue.pop().await.unwrap().is_none());
}

#[tokio::test]
async fn task_queue_stale_task_reclaimed() {
    let (conn, _container) = init_redis().await;

    // Consumer A: short idle timeout so the task becomes reclaimable quickly
    let queue_a = RedisTaskQueue::new(conn.clone())
        .with_consumer("consumer-a")
        .with_claim_idle_timeout(Duration::from_millis(200));

    // Consumer B: will reclaim stale tasks
    let queue_b = RedisTaskQueue::new(conn)
        .with_consumer("consumer-b")
        .with_claim_idle_timeout(Duration::from_millis(200));

    let task = make_task("ses_stale");
    queue_a.push(&task).await.unwrap();

    // A pops but never acks
    let popped_a = queue_a.pop().await.unwrap().unwrap();
    assert_eq!(popped_a.session_id, "ses_stale");

    // Wait for the idle timeout to expire
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B should be able to reclaim the stale task
    let popped_b = queue_b
        .pop()
        .await
        .unwrap()
        .expect("stale task should be reclaimed");
    assert_eq!(popped_b.session_id, "ses_stale");
    queue_b.ack(&popped_b).await.unwrap();
}

#[tokio::test]
async fn task_queue_concurrent_consumers_get_distinct_tasks() {
    let (conn, _container) = init_redis().await;

    // Push 4 tasks
    let queue = RedisTaskQueue::new(conn.clone());
    for i in 0..4 {
        queue
            .push(&make_task(&format!("ses_concurrent_{i}")))
            .await
            .unwrap();
    }

    // 4 consumers each pop one task
    let mut handles = Vec::new();
    for i in 0..4 {
        let q = RedisTaskQueue::new(conn.clone()).with_consumer(format!("worker-{i}"));
        handles.push(tokio::spawn(async move {
            let task = q.pop().await.unwrap();
            if let Some(t) = &task {
                q.ack(t).await.unwrap();
            }
            task.map(|t| t.session_id)
        }));
    }

    let mut session_ids: Vec<String> = Vec::new();
    for handle in handles {
        if let Some(id) = handle.await.unwrap() {
            session_ids.push(id);
        }
    }

    session_ids.sort();
    session_ids.dedup();
    assert_eq!(
        session_ids.len(),
        4,
        "each consumer should get a distinct task"
    );
}

// ── RedisEventPublisher + RedisEventSubscriber ───────────────────────────────

#[tokio::test]
async fn event_publish_subscribe_round_trip() {
    let (conn, push_rx, _container) = init_redis_resp3().await;

    let publisher = RedisEventPublisher::new(conn.clone());
    let subscriber = RedisEventSubscriber::new(conn, push_rx);

    let mut stream = subscriber.subscribe("ses_pubsub").await.unwrap();

    // Small delay for subscription to settle
    tokio::time::sleep(Duration::from_millis(50)).await;

    let processing = IssuanceEvent::Processing(SseProcessingEvent::new(
        "ses_pubsub",
        ProcessingStep::ExchangingToken,
    ));
    publisher.publish(&processing).await.unwrap();

    let completed = IssuanceEvent::Completed(SseCompletedEvent::new(
        "ses_pubsub",
        vec!["id1".into()],
        vec!["type1".into()],
    ));
    publisher.publish(&completed).await.unwrap();

    // Read events
    let e1 = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout waiting for processing event")
        .expect("stream ended prematurely");
    assert!(matches!(e1, IssuanceEvent::Processing(_)));

    let e2 = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout waiting for completed event")
        .expect("stream ended prematurely");
    assert!(matches!(e2, IssuanceEvent::Completed(_)));
}

#[tokio::test]
async fn event_terminal_completed_closes_stream() {
    let (conn, push_rx, _container) = init_redis_resp3().await;

    let publisher = RedisEventPublisher::new(conn.clone());
    let subscriber = RedisEventSubscriber::new(conn, push_rx);

    let mut stream = subscriber.subscribe("ses_terminal").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let completed =
        IssuanceEvent::Completed(SseCompletedEvent::new("ses_terminal", vec![], vec![]));
    publisher.publish(&completed).await.unwrap();

    // Should receive the completed event
    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream ended prematurely");
    assert!(matches!(event, IssuanceEvent::Completed(_)));

    // Stream should terminate after terminal event
    let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("timeout waiting for stream end");
    assert!(next.is_none(), "stream should close after terminal event");
}

#[tokio::test]
async fn event_failed_terminates_stream() {
    let (conn, push_rx, _container) = init_redis_resp3().await;

    let publisher = RedisEventPublisher::new(conn.clone());
    let subscriber = RedisEventSubscriber::new(conn, push_rx);

    let mut stream = subscriber.subscribe("ses_fail").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let failed = IssuanceEvent::Failed(SseFailedEvent::new(
        "ses_fail",
        "access_denied",
        Some("User denied".into()),
        IssuanceStep::Authorization,
    ));
    publisher.publish(&failed).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream ended prematurely");
    assert!(matches!(event, IssuanceEvent::Failed(_)));

    let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("timeout");
    assert!(next.is_none(), "stream should close after failed event");
}

#[tokio::test]
async fn event_subscriber_filters_by_session() {
    let (conn, push_rx, _container) = init_redis_resp3().await;

    let publisher = RedisEventPublisher::new(conn.clone());
    let subscriber = RedisEventSubscriber::new(conn, push_rx);

    // Subscribe to session A only
    let mut stream_a = subscriber.subscribe("ses_A").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish event for session B (should not appear on stream_a)
    let other = IssuanceEvent::Processing(SseProcessingEvent::new(
        "ses_B",
        ProcessingStep::ExchangingToken,
    ));
    publisher.publish(&other).await.unwrap();

    // Publish terminal event for session A
    let completed = IssuanceEvent::Completed(SseCompletedEvent::new("ses_A", vec![], vec![]));
    publisher.publish(&completed).await.unwrap();

    // stream_a should only receive ses_A's completed event
    let event = tokio::time::timeout(Duration::from_secs(5), stream_a.next())
        .await
        .expect("timeout")
        .expect("stream ended prematurely");
    assert!(matches!(event, IssuanceEvent::Completed(_)));
    assert_eq!(event.session_id(), "ses_A");
}

#[tokio::test]
async fn event_late_subscriber_misses_earlier_events() {
    let (conn, push_rx, _container) = init_redis_resp3().await;

    let publisher = RedisEventPublisher::new(conn.clone());
    let subscriber = RedisEventSubscriber::new(conn, push_rx);

    // Publish before subscribing
    let early = IssuanceEvent::Processing(SseProcessingEvent::new(
        "ses_late",
        ProcessingStep::ExchangingToken,
    ));
    publisher.publish(&early).await.unwrap();

    // Now subscribe
    let mut stream = subscriber.subscribe("ses_late").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish a terminal event so the stream can complete
    let completed = IssuanceEvent::Completed(SseCompletedEvent::new("ses_late", vec![], vec![]));
    publisher.publish(&completed).await.unwrap();

    // The first event received should be the completed event, not the early one
    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timeout")
        .expect("stream ended prematurely");
    assert!(
        matches!(event, IssuanceEvent::Completed(_)),
        "late subscriber should not receive events published before subscription"
    );
}
