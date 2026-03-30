use super::*;
use std::time::Duration;

#[tokio::test]
async fn test_cache_insertion_and_retrieval() {
    let cache: Cache<String, String> = Cache::new(10);
    cache.insert("key1".to_string(), "value1".to_string()).await;
    assert_eq!(cache.get("key1").await, Some("value1".to_string()));
    assert_eq!(cache.get("key2").await, None);
}

#[tokio::test]
async fn test_cache_max_capacity() {
    let cache: Cache<i32, i32> = Cache::new(2);
    cache.insert(1, 1).await;
    cache.insert(2, 2).await;
    // This should evict one of the previous entries
    cache.insert(3, 3).await;
    // Run pending tasks to process eviction
    cache.run_pending_tasks().await;
    assert_eq!(cache.entry_count(), 2);
}

#[tokio::test]
async fn test_cache_ttl() {
    let cache: Cache<i32, i32> = Cache::builder()
        .max_capacity(10)
        .time_to_live(Duration::from_millis(50))
        .build();
    cache.insert(1, 1).await;
    assert_eq!(cache.get(&1).await, Some(1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(cache.get(&1).await, None);
}

#[tokio::test]
async fn test_cache_tti() {
    let cache: Cache<i32, i32> = Cache::builder()
        .max_capacity(10)
        .time_to_idle(Duration::from_millis(50))
        .build();
    cache.insert(1, 1).await;
    assert_eq!(cache.get(&1).await, Some(1));
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(cache.get(&1).await, Some(1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(cache.get(&1).await, None);
}

#[tokio::test]
async fn test_cache_max_accesses() {
    let cache: Cache<i32, i32> = Cache::builder().max_capacity(10).max_accesses(3).build();
    cache.insert(1, 1).await;
    assert_eq!(cache.get(&1).await, Some(1)); // 1
    assert_eq!(cache.get(&1).await, Some(1)); // 2
    assert_eq!(cache.get(&1).await, Some(1)); // 3
    assert_eq!(cache.get(&1).await, None); // 4 evicts
}

#[tokio::test]
async fn test_cache_get_or_insert() {
    let cache: Cache<&str, i32> = Cache::new(10);
    let value1 = cache.get_or_insert("key", async { 100 }).await;
    assert_eq!(value1, 100);
    let value2 = cache.get_or_insert("key", async { 999 }).await;
    assert_eq!(value2, 100);
}

#[tokio::test]
async fn test_cache_invalidation() {
    let cache: Cache<i32, i32> = Cache::new(10);
    cache.insert(1, 1).await;
    assert_eq!(cache.get(&1).await, Some(1));
    cache.invalidate(&1).await;
    assert_eq!(cache.get(&1).await, None);
}

#[tokio::test]
async fn test_cache_stats() {
    let cache: Cache<&str, i32> = Cache::builder().max_capacity(10).enable_stats(true).build();
    cache.insert("key1", 1).await;
    let _ = cache.get("key1").await; // Hit
    let _ = cache.get("key2").await; // Miss
    let stats = cache.stats().await;
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hit_rate(), 0.5);
}
