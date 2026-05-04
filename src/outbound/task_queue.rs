use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use redis::streams::{
    StreamAddOptions, StreamAutoClaimOptions, StreamId, StreamReadOptions, StreamReadReply,
    StreamTrimStrategy, StreamTrimmingMode,
};
use redis::{AsyncCommands, Value, aio::ConnectionManager};

use crate::domain::models::issuance::{IssuanceError, IssuanceTask};
use crate::domain::ports::IssuanceTaskQueue;

/// Key for the issuance task queue stream in Redis.
const TASK_STREAM_KEY: &str = "issuance:task_stream";
const TASK_STREAM_GROUP: &str = "issuance-workers";
const TASK_STREAM_PAYLOAD_FIELD: &str = "payload";
const DEFAULT_STREAM_MAX_LEN: usize = 10_000;
const DEFAULT_CLAIM_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Redis-backed distributed task queue.
#[derive(Debug, Clone)]
pub struct RedisTaskQueue {
    conn: ConnectionManager,
    group: &'static str,
    consumer: String,
    max_len: usize,
    claim_idle_timeout: Duration,
}

impl RedisTaskQueue {
    /// Create a new task queue with a Redis connection manager.
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            group: TASK_STREAM_GROUP,
            consumer: default_consumer_name(),
            max_len: DEFAULT_STREAM_MAX_LEN,
            claim_idle_timeout: DEFAULT_CLAIM_IDLE_TIMEOUT,
        }
    }

    /// Override the Redis consumer group name.
    ///
    /// The default value is "issuance-workers"
    pub fn with_group(self, group: &'static str) -> Self {
        Self { group, ..self }
    }

    /// Override the Redis consumer name for this worker.
    pub fn with_consumer(self, consumer: impl Into<String>) -> Self {
        Self {
            consumer: consumer.into(),
            ..self
        }
    }

    /// Cap the stream length during stream insertion.
    pub fn with_max_len(self, max_len: usize) -> Self {
        Self {
            max_len: max_len.max(1),
            ..self
        }
    }

    /// Override how long a pending task must be idle before this worker may reclaim it.
    ///
    /// The default value is 5 minutes.
    pub fn with_claim_idle_timeout(self, timeout: Duration) -> Self {
        Self {
            claim_idle_timeout: timeout,
            ..self
        }
    }

    // Ensure the consumer group exists for the task stream
    async fn ensure_group(&self) -> Result<(), IssuanceError> {
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> = conn
            .xgroup_create_mkstream(TASK_STREAM_KEY, self.group, "0")
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(e) if e.code() == Some("BUSYGROUP") => Ok(()),
            Err(e) => Err(map_redis_err(e)),
        }
    }

    /// Claim any stale tasks that are still in the stream
    async fn claim_stale_task(&self) -> Result<Option<IssuanceTask>, IssuanceError> {
        let min_idle_ms = self.claim_idle_timeout.as_millis().min(usize::MAX as u128) as usize;
        let options = StreamAutoClaimOptions::default().count(1);
        let mut conn = self.conn.clone();
        let reply: redis::streams::StreamAutoClaimReply = conn
            .xautoclaim_options(
                TASK_STREAM_KEY,
                self.group,
                self.consumer.as_str(),
                min_idle_ms,
                "0-0",
                options,
            )
            .await
            .map_err(map_redis_err)?;

        let Some(entry) = reply.claimed.first() else {
            return Ok(None);
        };
        Ok(Some(task_from_stream_entry(entry)?))
    }
}

#[async_trait]
impl IssuanceTaskQueue for RedisTaskQueue {
    async fn push(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        let json = task.to_json()?;

        self.ensure_group().await?;
        let mut conn = self.conn.clone();
        let options = StreamAddOptions::default().trim(StreamTrimStrategy::maxlen(
            StreamTrimmingMode::Approx,
            self.max_len,
        ));
        let _: Option<String> = conn
            .xadd_options(
                TASK_STREAM_KEY,
                "*",
                &[(TASK_STREAM_PAYLOAD_FIELD, json)],
                &options,
            )
            .await
            .map_err(map_redis_err)?;
        Ok(())
    }

    async fn pop(&self) -> Result<Option<IssuanceTask>, IssuanceError> {
        self.ensure_group().await?;

        // First, try to claim any stale tasks that are still in the stream
        if let Some(task) = self.claim_stale_task().await? {
            return Ok(Some(task));
        }

        let mut conn = self.conn.clone();
        let options = StreamReadOptions::default()
            .group(self.group, self.consumer.as_str())
            .count(1);

        let reply: Option<StreamReadReply> = conn
            .xread_options(&[TASK_STREAM_KEY], &[">"], &options)
            .await
            .map_err(map_redis_err)?;

        let Some(reply) = reply else {
            return Ok(None);
        };
        let Some(stream) = reply.keys.first() else {
            return Ok(None);
        };
        let Some(entry) = stream.ids.first() else {
            return Ok(None);
        };
        Ok(Some(task_from_stream_entry(entry)?))
    }

    async fn ack(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        let Some(queue_id) = task.queue_id.as_deref() else {
            return Ok(());
        };

        let mut conn = self.conn.clone();
        let _: usize = conn
            .xack(TASK_STREAM_KEY, self.group, &[queue_id])
            .await
            .map_err(map_redis_err)?;
        let _: usize = conn
            .xdel(TASK_STREAM_KEY, &[queue_id])
            .await
            .map_err(map_redis_err)?;
        Ok(())
    }
}

fn default_consumer_name() -> String {
    format!("worker-{}-{}", std::process::id(), uuid::Uuid::new_v4())
}

fn task_from_stream_entry(entry: &StreamId) -> Result<IssuanceTask, IssuanceError> {
    let Some(payload) = entry.map.get(TASK_STREAM_PAYLOAD_FIELD) else {
        return Err(IssuanceError::internal_message(
            "Redis stream task entry is missing payload",
        ));
    };

    let bytes = payload_bytes(payload)?;
    let mut task = IssuanceTask::from_json(bytes)?;
    task.queue_id = Some(entry.id.clone());
    Ok(task)
}

fn payload_bytes(value: &Value) -> Result<&[u8], IssuanceError> {
    match value {
        Value::BulkString(bytes) => Ok(bytes),
        Value::SimpleString(value) => Ok(value.as_bytes()),
        other => Err(IssuanceError::internal_message(format!(
            "Redis stream task payload has unexpected type: {other:?}"
        ))),
    }
}

/// Maps a `redis::RedisError` into an `IssuanceError`.
fn map_redis_err(err: redis::RedisError) -> IssuanceError {
    IssuanceError::internal(err)
}

/// In-memory task queue mainly designed for testing and development.
#[derive(Debug)]
pub struct MemoryTaskQueue {
    queue: Mutex<VecDeque<IssuanceTask>>,
}

impl MemoryTaskQueue {
    /// Create a new empty in-memory task queue.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }
}

impl Default for MemoryTaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IssuanceTaskQueue for MemoryTaskQueue {
    async fn push(&self, task: &IssuanceTask) -> Result<(), IssuanceError> {
        let mut queue = self.queue.lock().expect("lock poisoned");
        queue.push_back(task.clone());
        Ok(())
    }

    async fn pop(&self) -> Result<Option<IssuanceTask>, IssuanceError> {
        let task = {
            let mut queue = self.queue.lock().expect("lock poisoned");
            queue.pop_front()
        };

        let Some(task) = task else {
            return Ok(None);
        };
        Ok(Some(task))
    }

    async fn ack(&self, _task: &IssuanceTask) -> Result<(), IssuanceError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::FlowType;
    use uuid::Uuid;

    fn make_task(session_id: &str) -> IssuanceTask {
        IssuanceTask {
            queue_id: None,
            session_id: session_id.to_owned(),
            tenant_id: Uuid::new_v4(),
            flow: FlowType::PreAuthorizedCode,
            authorization_code: None,
            pkce_verifier: None,
            pre_authorized_code: Some("pre_code".into()),
            tx_code: None,
        }
    }

    #[tokio::test]
    async fn memory_queue_push_pop_fifo() {
        let queue = MemoryTaskQueue::new();
        let t1 = make_task("ses_1");
        let t2 = make_task("ses_2");

        queue.push(&t1).await.unwrap();
        queue.push(&t2).await.unwrap();

        let popped1 = queue.pop().await.unwrap().unwrap();
        assert_eq!(popped1.session_id, "ses_1");

        let popped2 = queue.pop().await.unwrap().unwrap();
        assert_eq!(popped2.session_id, "ses_2");

        // Queue is now empty
        assert!(queue.pop().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_queue_push_twice_pops_twice() {
        let queue = MemoryTaskQueue::new();
        let t1 = make_task("ses_1");

        // Push same session twice
        queue.push(&t1).await.unwrap();
        queue.push(&t1).await.unwrap();

        // Both copies are popped
        let popped1 = queue.pop().await.unwrap();
        assert!(popped1.is_some());

        let popped2 = queue.pop().await.unwrap();
        assert!(popped2.is_some());

        // Queue is now empty
        assert!(queue.pop().await.unwrap().is_none());
    }
}
