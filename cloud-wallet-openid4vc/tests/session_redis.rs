//! Integration tests for the Redis session store.
//!
//! These tests spin up a Redis container via `testcontainers-modules` and require
//! Docker to be running. They are gated behind the `session-redis` feature flag.

#![cfg(feature = "session-redis")]

use cloud_wallet_openid4vc::session::{
    SessionStore, SessionStoreError,
    model::{DEFAULT_SESSION_TTL_SECS, IssuanceSession, IssuanceSessionState},
    redis::RedisSessionStore,
};
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

async fn make_store() -> (RedisSessionStore, impl Drop) {
    let container = Redis::default()
        .start()
        .await
        .expect("Failed to start Redis container");

    let port = container
        .get_host_port_ipv4(6379)
        .await
        .expect("redis port");

    let url = format!("redis://127.0.0.1:{port}/");
    let client = redis::Client::open(url).unwrap();
    let store = RedisSessionStore::new(client).await.unwrap();

    (store, container)
}

fn sample_session() -> IssuanceSession {
    IssuanceSession::new(
        Uuid::new_v4(),
        "https://issuer.example".to_string(),
        vec!["eu.europa.ec.eudi.pid.1".to_string()],
        DEFAULT_SESSION_TTL_SECS,
    )
}

#[tokio::test]
async fn redis_create_get_roundtrip() {
    let (store, _container) = make_store().await;

    let session = sample_session();
    let id = session.session_id.clone();

    store.create(session.clone()).await.unwrap();

    let found = store.get(&id).await.unwrap();
    assert_eq!(found.session_id, session.session_id);
    assert_eq!(found.tenant_id, session.tenant_id);
    assert_eq!(found.credential_issuer, session.credential_issuer);
}

#[tokio::test]
async fn redis_get_nonexistent_returns_not_found() {
    let (store, _container) = make_store().await;
    let err = store.get("does-not-exist").await.unwrap_err();
    assert!(
        matches!(err, SessionStoreError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn redis_consume_atomic() {
    let (store, _container) = make_store().await;
    let session = sample_session();
    let id = session.session_id.clone();

    store.create(session.clone()).await.unwrap();

    // First consume succeeds
    let consumed = store.consume(&id).await.unwrap();
    assert_eq!(consumed.session_id, id);

    // Second consume returns NotFound
    let err = store.consume(&id).await.unwrap_err();
    assert!(
        matches!(err, SessionStoreError::NotFound { .. }),
        "expected NotFound after consume, got {err:?}"
    );
}

#[tokio::test]
async fn redis_update_persists() {
    let (store, _container) = make_store().await;
    let mut session = sample_session();
    let id = session.session_id.clone();

    store.create(session.clone()).await.unwrap();

    session.state = IssuanceSessionState::Completed;
    store.update(&session).await.unwrap();

    let found = store.get(&id).await.unwrap();
    assert_eq!(found.state, IssuanceSessionState::Completed);
}

#[tokio::test]
async fn redis_update_nonexistent_returns_not_found() {
    let (store, _container) = make_store().await;
    let session = sample_session();
    let err = store.update(&session).await.unwrap_err();
    assert!(
        matches!(err, SessionStoreError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn redis_delete_removes_key() {
    let (store, _container) = make_store().await;
    let session = sample_session();
    let id = session.session_id.clone();

    store.create(session).await.unwrap();
    store.delete(&id).await.unwrap();

    let err = store.get(&id).await.unwrap_err();
    assert!(matches!(err, SessionStoreError::NotFound { .. }));
}

#[tokio::test]
async fn redis_delete_nonexistent_returns_not_found() {
    let (store, _container) = make_store().await;
    let err = store.delete("ghost-id").await.unwrap_err();
    assert!(matches!(err, SessionStoreError::NotFound { .. }));
}

#[tokio::test]
async fn redis_ttl_expiration_detected_on_read() {
    let (store, _container) = make_store().await;

    // Create a session that is already expired (ttl = -1)
    let session = IssuanceSession::new(
        Uuid::new_v4(),
        "https://issuer.example".to_string(),
        vec![],
        -1, // already in the past
    );
    let id = session.session_id.clone();

    // create() with zero-TTL should either not store or store with TTL=0
    store.create(session).await.unwrap();

    // get() should detect expiry (either NotFound because store skipped it,
    // or Expired because wall-clock check fires)
    let err = store.get(&id).await.unwrap_err();
    assert!(
        matches!(
            err,
            SessionStoreError::Expired { .. } | SessionStoreError::NotFound { .. }
        ),
        "expected Expired or NotFound for past session, got {err:?}"
    );
}
