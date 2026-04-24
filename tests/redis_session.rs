use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cloud_identity_wallet::session::{RedisSession, SessionStore};
use redis::Client;
use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
};
use tokio::sync::Barrier;
use uuid::Uuid;

async fn init_session_store(ttl: Duration) -> (RedisSession, ContainerAsync<Redis>) {
    let container = Redis::default()
        .with_tag("8-alpine")
        .start()
        .await
        .expect("redis container failed to start");

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
    let connection_string = format!("redis://{host}:{port}");

    let client = Client::open(connection_string).expect("failed to create redis client");
    let conn = client
        .get_connection_manager()
        .await
        .expect("failed to get redis connection manager");

    let session = RedisSession::new(conn)
        .with_prefix(format!("session-test-{}", Uuid::new_v4()))
        .with_ttl(ttl);

    (session, container)
}

#[tokio::test]
async fn redis_roundtrip_and_remove() {
    let (store, _container) = init_session_store(Duration::from_secs(2)).await;
    let key = b"session";

    store.upsert(key, &b"value".to_vec()).await.unwrap();
    assert!(store.exists(key).await.unwrap());
    let val: Option<Vec<u8>> = store.get(key).await.unwrap();
    assert_eq!(val, Some(b"value".to_vec()));

    store.remove(key).await.unwrap();
    assert!(!store.exists(key).await.unwrap());
    let val: Option<Vec<u8>> = store.get(key).await.unwrap();
    assert_eq!(val, None);
}

#[tokio::test]
async fn redis_consumes_only_once() {
    let (store, _container) = init_session_store(Duration::from_secs(2)).await;
    let key = b"one-time";

    store.upsert(key, &b"value".to_vec()).await.unwrap();
    let val: Option<Vec<u8>> = store.consume(key).await.unwrap();
    assert_eq!(val, Some(b"value".to_vec()));
    let val2: Option<Vec<u8>> = store.get(key).await.unwrap();
    assert_eq!(val2, None);
}

#[tokio::test]
async fn redis_upsert_does_not_extend_ttl() {
    let (store, _container) = init_session_store(Duration::from_millis(220)).await;
    let key = b"ttl-no-refresh";

    store.upsert(key, &b"v1".to_vec()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(130)).await;

    store.upsert(key, &b"v2".to_vec()).await.unwrap();
    let val: Option<Vec<u8>> = store.get(key).await.unwrap();
    assert_eq!(val, Some(b"v2".to_vec()));

    tokio::time::sleep(Duration::from_millis(120)).await;
    let val: Option<Vec<u8>> = store.get(key).await.unwrap();
    assert_eq!(val, None);
}

#[tokio::test]
async fn redis_consume_is_atomic_for_concurrent_callers() {
    let (store, _container) = init_session_store(Duration::from_secs(2)).await;
    let store = Arc::new(store);
    let key = b"race-consume";
    store.upsert(key, &b"value".to_vec()).await.unwrap();

    let callers = 24usize;
    let barrier = Arc::new(Barrier::new(callers));
    let success_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(callers);

    for _ in 0..callers {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let success_count = Arc::clone(&success_count);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let val: Option<Vec<u8>> = store.consume(key).await.unwrap();
            if val.is_some() {
                success_count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(success_count.load(Ordering::Relaxed), 1);
}
