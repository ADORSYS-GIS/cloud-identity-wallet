//! A fast, concurrent cache with advanced eviction policies.
//!
//! # Eviction Policies
//!
//! * Max Capacity: Evicts the oldest entries when the cache reaches its maximum capacity.
//! * Time-to-Live (TTL): Evicts entries after a specified time-to-live period.
//! * Time-to-Idle (TTI): Evicts entries after a specified time-to-idle period.
//! * Custom Access Limits: Ability to set specific access limits on individual entries
//!   using [`Cache::insert_with_max_accesses`] or globally using [`CacheBuilder::max_accesses`].
//!
//! # Hasher
//!
//! The cache uses [ahash](https://crates.io/crates/ahash) as the default hasher,
//! which provides high-performance hashing with resistance to hash collision attacks.
//! A custom hasher can be provided using the [`CacheBuilder::build_with_hasher`] method.

#[cfg(test)]
mod tests;

use std::borrow::Borrow;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ahash::RandomState;
use dashmap::DashMap;
use moka::future::Cache as MokaCache;

/// A concurrent, fast, async-aware cache with support for custom eviction policies and statistics.
///
/// All cached values are cloned when retrieved. To avoid expensive clones, users are encouraged
/// to wrap the values in `Arc`. `Arc<Mutex<T>>` or `Arc<RwLock<T>>` can be used if interior mutability is needed.
pub struct Cache<K, V, S = RandomState> {
    inner: MokaCache<K, V, S>,
    stats: CacheStatsRef,
    enable_stats: bool,
    access_counters: Arc<DashMap<K, AccessCounter, S>>,
    max_accesses: Option<u64>,
}

impl<K, V> Cache<K, V, RandomState>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new `Cache` with the specified maximum capacity.
    pub fn new(max_capacity: u64) -> Self {
        CacheBuilder::new(max_capacity).build()
    }

    /// Returns a [`CacheBuilder`] to configure and create a [`Cache`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use cloud_wallet_kms::cache::Cache;
    /// let cache: Cache<&str, i32> = Cache::builder()
    ///     .max_capacity(1_000)
    ///     .time_to_live(Duration::from_secs(60))
    ///     .build();
    /// ```
    pub fn builder() -> CacheBuilder<K, V, Cache<K, V, RandomState>> {
        CacheBuilder::default()
    }
}

impl<K, V, S> Cache<K, V, S>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    S: BuildHasher + Clone + Send + Sync + 'static,
{
    /// Returns `true` if the cache contains a value for the specified key.
    ///
    /// Note that this method does not update the access statistics or access counters,
    /// and it does not guarantee that a subsequent call to [`get`](Self::get) will succeed,
    /// as the entry could be evicted concurrently.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&str, i32> = Cache::new(5);
    /// cache.insert("key", 42).await;
    /// assert!(cache.contains("key"));
    /// # }
    /// ```
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.contains_key(key)
    }

    /// Returns the cloned value associated with the key.
    ///
    /// If you want to avoid expensive clone, you can wrap the value in an [`Arc`],
    /// making the clone cheap.
    ///
    /// This method updates access statistics (hits/misses) and increments the
    /// access counter for the key if one is set. If the access limit is reached,
    /// the entry is evicted before returning `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&str, i32> = Cache::new(5);
    /// cache.insert("key", 42).await;
    ///
    /// assert_eq!(cache.get("key").await, Some(42));
    /// assert_eq!(cache.get("non-existent").await, None);
    /// # }
    /// ```
    pub async fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let result = self.inner.get(key).await;
        let is_stats_enabled = self.enable_stats;

        if result.is_some() {
            // Increment access counter
            let should_evict = {
                let counters = &self.access_counters;
                if let Some(counter) = counters.get(key) {
                    counter.increment();
                    counter.should_evict()
                } else {
                    false
                }
            };

            // Evict if access limit reached
            if should_evict {
                self.remove(key).await;
                self.stats.record_eviction();
                return None;
            }
            if is_stats_enabled {
                self.stats.record_hit();
            }
        } else if is_stats_enabled {
                self.stats.record_miss();
            
        }
        result
    }

    /// Inserts a key-value pair into the cache.
    ///
    /// If the cache already has an entry for the key, the old value is replaced
    /// and the access counter is reset according to the global max accesses policy
    /// (if configured on the builder).
    pub async fn insert(&self, key: K, value: V) {
        // Initialize access counter
        let counters = &self.access_counters;
        counters.insert(key.clone(), AccessCounter::new(self.max_accesses));

        self.inner.insert(key, value).await;
    }

    /// Inserts a key-value pair with a specific access limit.
    ///
    /// The entry will be evicted after it has been accessed `max_accesses` times.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&'static str, Vec<u8>> = Cache::new(10);
    /// // This specific entry will be evicted after it has been retrieved 5 times.
    /// cache.insert_with_max_accesses("single_use_token", vec![1, 2, 3], 5).await;
    /// # }
    /// ```
    pub async fn insert_with_max_accesses(&self, key: K, value: V, max_accesses: u64) {
        // Initialize access counter with specific limit
        let counters = &self.access_counters;
        counters.insert(key.clone(), AccessCounter::new(Some(max_accesses)));

        self.inner.insert(key, value).await;
    }

    /// Returns the value associated with the key if it exists,
    /// otherwise resolves the provided future `init`, inserts the output into the cache,
    /// and returns the value.
    ///
    /// This method is useful for _read-through_ caching patterns, where multiple concurrent
    /// requests for the same missing key will only cause the `init` future to be executed once.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&str, i32> = Cache::new(10);
    ///
    /// // The future is executed because "key" is not in the cache.
    /// let value1 = cache.get_or_insert("key", async { 100 }).await;
    /// assert_eq!(value1, 100);
    ///
    /// // The future is NOT executed; the cached value is returned.
    /// let value2 = cache.get_or_insert("key", async { 999 }).await;
    /// assert_eq!(value2, 100);
    /// # }
    /// ```
    pub async fn get_or_insert<F>(&self, key: K, init: F) -> V
    where
        F: Future<Output = V>,
    {
        let entry = self.inner.entry(key.clone()).or_insert_with(init).await;
        let is_stats_enabled = self.enable_stats;

        if entry.is_fresh() {
            if is_stats_enabled {
                self.stats.record_miss();
            }
            // Initialize access counter for new entry
            let counters = &self.access_counters;
            counters.insert(key, AccessCounter::new(self.max_accesses));
        } else {
            if is_stats_enabled {
                self.stats.record_hit();
            }
            // Increment access counter
            let counters = &self.access_counters;
            if let Some(counter) = counters.get(&key) {
                counter.increment();
            }
        }
        entry.into_value()
    }

    /// Asynchronously invalidates (removes) an entry from the cache.
    ///
    /// The entry is removed concurrently in the background. If you need to immediately
    /// remove the entry and obtain its value, use [`remove`](Self::remove) instead.
    pub async fn invalidate<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        // Remove access counter
        let counters = &self.access_counters;
        counters.remove(key);
        self.inner.invalidate(key).await
    }

    /// Removes an entry from the cache, returning the cloned value if it existed.
    ///
    /// Unlike [`invalidate`](Self::invalidate), this method waits for the entry to be
    /// removed and returns the value that was stored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&str, i32> = Cache::new(10);
    /// cache.insert("key", 42).await;
    ///
    /// assert_eq!(cache.remove("key").await, Some(42));
    /// assert_eq!(cache.remove("key").await, None);
    /// # }
    /// ```
    pub async fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        // Remove access counter
        let counters = &self.access_counters;
        counters.remove(key);
        self.inner.remove(key).await
    }

    /// Removes all entries from the cache.
    pub async fn invalidate_all(&self) {
        self.inner.invalidate_all();
        // Clear access counters
        let counters = &self.access_counters;
        counters.clear();
        // Run pending tasks to ensure evictions are processed
        self.inner.run_pending_tasks().await;
    }

    /// Returns the approximate number of entries in the cache.
    ///
    /// Note: This is an estimate and may not be strictly accurate due to concurrent
    /// operations and pending evictions. If you need a more accurate count, consider
    /// calling [`run_pending_tasks()`](Self::run_pending_tasks) before this method,
    /// though it is still not guaranteed to be exact in highly concurrent scenarios.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    /// Returns the [`Policy`] configured for this cache.
    pub fn policy(&self) -> Policy {
        Policy {
            max_capacity: self.inner.policy().max_capacity(),
            time_to_live: self.inner.policy().time_to_live(),
            time_to_idle: self.inner.policy().time_to_idle(),
            max_accesses: self.max_accesses,
        }
    }

    /// Returns a snapshot of the cache's performance statistics.
    ///
    /// The statistics include hits, misses, and evictions. Tracking these must be
    /// enabled via [`CacheBuilder::enable_stats`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::Cache;
    /// # #[pollster::main]
    /// # async fn main() {
    /// let cache: Cache<&str, i32> = Cache::builder()
    ///     .max_capacity(10)
    ///     .enable_stats(true)
    ///     .build();
    ///
    /// cache.insert("key1", 1).await;
    /// let _ = cache.get("key1").await; // Hit
    /// let _ = cache.get("key2").await; // Miss
    ///
    /// let stats = cache.stats().await;
    /// assert_eq!(stats.hits, 1);
    /// assert_eq!(stats.misses, 1);
    /// assert_eq!(stats.hit_rate(), 0.5);
    /// # }
    /// ```
    pub async fn stats(&self) -> CacheStats {
        self.stats.snapshot().await
    }

    /// Returns an iterator visiting all key-value pairs in arbitrary order.
    ///
    /// The iterator yields `(Arc<K>, V)` where the key is wrapped in an `Arc` to
    /// avoid cloning the key itself.
    pub fn iter(&self) -> impl Iterator<Item = (Arc<K>, V)> {
        self.inner.iter()
    }

    /// Runs all pending maintenance operations in the cache.
    ///
    /// This could be useful in tests to ensure evictions and expirations are processed.
    pub async fn run_pending_tasks(&self) {
        self.inner.run_pending_tasks().await;
    }
}

impl<K, V, S> fmt::Debug for Cache<K, V, S>
where
    K: fmt::Debug + Eq + Hash + Send + Sync + 'static,
    V: fmt::Debug + Clone + Send + Sync + 'static,
    S: BuildHasher + Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cache")
            .field("inner", &self.inner)
            .field("stats", &self.stats)
            .field("access_counters", &self.access_counters)
            .field("max_accesses", &self.max_accesses)
            .finish()
    }
}

// We avoid `#[derive(Clone)]` because it will add `Clone` bound to `K`.
impl<K, V, S> Clone for Cache<K, V, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            stats: self.stats.clone(),
            enable_stats: self.enable_stats,
            access_counters: self.access_counters.clone(),
            max_accesses: self.max_accesses,
        }
    }
}

/// Access counter for tracking entry usage.
#[derive(Debug, Clone)]
struct AccessCounter {
    count: Arc<AtomicU64>,
    max_accesses: Option<u64>,
}

impl AccessCounter {
    fn new(max_accesses: Option<u64>) -> Self {
        Self {
            count: Arc::new(AtomicU64::new(0)),
            max_accesses,
        }
    }

    fn increment(&self) -> u64 {
        self.count.fetch_add(1, Ordering::Release) + 1
    }

    fn get(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    fn should_evict(&self) -> bool {
        if let Some(max) = self.max_accesses {
            self.get() > max
        } else {
            false
        }
    }
}

/// A builder for configuring and creating a [`Cache`].
///
/// # Default Values
///
/// * Maximum capacity: `None` (unbounded)
/// * Time to live: `None` (entries don't expire based on absolute time)
/// * Time to idle: `None` (entries don't expire based on idle time)
/// * Max accesses: `None` (entries are not evicted based on read counts)
/// * Statistics: `false` (statistics are disabled)
#[derive(Debug)]
pub struct CacheBuilder<K, V, C> {
    max_capacity: Option<u64>,
    time_to_live: Option<Duration>,
    time_to_idle: Option<Duration>,
    max_accesses: Option<u64>,
    enable_stats: bool,
    _phantom: std::marker::PhantomData<(K, V, C)>,
}

impl<K, V> CacheBuilder<K, V, Cache<K, V, RandomState>>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new builder with the specified maximum capacity.
    pub fn new(max_capacity: u64) -> Self {
        Self {
            max_capacity: Some(max_capacity),
            ..Default::default()
        }
    }

    /// Sets the maximum capacity of the cache.
    ///
    /// When the cache reaches this capacity, it will begin evicting entries based
    /// on its internal policy (TinyLFU).
    pub fn max_capacity(self, max_capacity: u64) -> Self {
        Self {
            max_capacity: Some(max_capacity),
            ..self
        }
    }

    /// Sets the time-to-live (TTL) policy for entries.
    ///
    /// Entries will expire and be evicted automatically after this duration has
    /// passed since they were inserted or last updated.
    pub fn time_to_live(self, duration: Duration) -> Self {
        Self {
            time_to_live: Some(duration),
            ..self
        }
    }

    /// Sets the time-to-idle (TTI) policy for entries.
    ///
    /// Entries will expire and be evicted automatically if they have not been
    /// accessed (read or updated) for this duration.
    pub fn time_to_idle(self, duration: Duration) -> Self {
        Self {
            time_to_idle: Some(duration),
            ..self
        }
    }

    /// Enables or disables tracking of cache statistics (hits, misses, evictions).
    pub fn enable_stats(self, enable: bool) -> Self {
        Self {
            enable_stats: enable,
            ..self
        }
    }

    /// Sets the maximum number of accesses globally for all entries.
    ///
    /// When an entry is read this many times via [`Cache::get`] or [`Cache::get_or_insert`],
    /// it will be automatically evicted. This policy can be overridden for specific
    /// entries using [`Cache::insert_with_max_accesses`].
    pub fn max_accesses(self, max_accesses: u64) -> Self {
        Self {
            max_accesses: Some(max_accesses),
            ..self
        }
    }

    /// Builds the cache with the configured options.
    ///
    /// # Panics
    ///
    /// Panics if configured with either `time_to_live` or `time_to_idle` higher than
    /// 1000 years. This is done to protect against overflow when computing key
    /// expiration.
    pub fn build(self) -> Cache<K, V, RandomState> {
        let build_hasher = RandomState::new();
        self.build_inner(build_hasher)
    }

    /// Builds the cache using a custom hasher.
    ///
    /// This is useful if you want to use a specific hashing algorithm instead of
    /// the default `RandomState` provided by `ahash`.
    pub fn build_with_hasher<H>(self, hasher: H) -> Cache<K, V, H>
    where
        H: BuildHasher + Clone + Send + Sync + 'static,
    {
        self.build_inner(hasher)
    }

    fn build_inner<H>(self, hasher: H) -> Cache<K, V, H>
    where
        H: BuildHasher + Clone + Send + Sync + 'static,
    {
        let stats = CacheStatsRef::new();
        let mut builder = MokaCache::builder();

        if let Some(capacity) = self.max_capacity {
            builder = builder.max_capacity(capacity);
        }
        if let Some(ttl) = self.time_to_live {
            builder = builder.time_to_live(ttl);
        }
        if let Some(tti) = self.time_to_idle {
            builder = builder.time_to_idle(tti);
        }

        // Add eviction listener for statistics
        if self.enable_stats {
            let stats_clone = stats.clone();
            builder = builder.eviction_listener(move |_key, _value, _cause| {
                stats_clone.record_eviction();
            });
        }

        Cache {
            inner: builder.build_with_hasher(hasher.clone()),
            stats,
            enable_stats: self.enable_stats,
            access_counters: Arc::new(DashMap::with_hasher(hasher)),
            max_accesses: self.max_accesses,
        }
    }
}

impl<K, V> Default for CacheBuilder<K, V, Cache<K, V, RandomState>>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self {
            max_capacity: None,
            time_to_live: None,
            time_to_idle: None,
            max_accesses: None,
            enable_stats: false,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Represents the configuration policies applied to a [`Cache`].
///
/// This struct provides read-only access to the policies configured.
#[derive(Clone, Debug)]
pub struct Policy {
    max_capacity: Option<u64>,
    time_to_live: Option<Duration>,
    time_to_idle: Option<Duration>,
    max_accesses: Option<u64>,
}

impl Policy {
    /// Returns the maximum capacity of the cache.
    pub fn max_capacity(&self) -> Option<u64> {
        self.max_capacity
    }

    /// Returns the time to live configuration of the cache.
    pub fn time_to_live(&self) -> Option<Duration> {
        self.time_to_live
    }

    /// Returns the time to idle configuration of the cache.
    pub fn time_to_idle(&self) -> Option<Duration> {
        self.time_to_idle
    }

    /// Returns the maximum accesses configuration of the cache.
    pub fn max_accesses(&self) -> Option<u64> {
        self.max_accesses
    }
}

/// Thread-safe cache statistics tracker.
#[derive(Clone)]
struct CacheStatsRef {
    inner: Arc<CacheStatsInner>,
}

struct CacheStatsInner {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl CacheStatsRef {
    fn new() -> Self {
        Self {
            inner: Arc::new(CacheStatsInner {
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                evictions: AtomicU64::new(0),
            }),
        }
    }

    fn record_hit(&self) {
        self.inner.hits.fetch_add(1, Ordering::Release);
    }

    fn record_miss(&self) {
        self.inner.misses.fetch_add(1, Ordering::Release);
    }

    fn record_eviction(&self) {
        self.inner.evictions.fetch_add(1, Ordering::Release);
    }

    async fn snapshot(&self) -> CacheStats {
        CacheStats {
            hits: self.inner.hits.load(Ordering::Acquire),
            misses: self.inner.misses.load(Ordering::Acquire),
            evictions: self.inner.evictions.load(Ordering::Acquire),
        }
    }
}

impl Default for CacheStatsRef {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CacheStatsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheStatsRef")
            .field("hits", &self.inner.hits.load(Ordering::SeqCst))
            .field("misses", &self.inner.misses.load(Ordering::SeqCst))
            .field("evictions", &self.inner.evictions.load(Ordering::SeqCst))
            .finish()
    }
}

/// A snapshot of cache performance statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Total number of evictions.
    pub evictions: u64,
}

impl CacheStats {
    /// Returns the cache hit rate as a value between 0.0 and 1.0.
    ///
    /// Returns 0.0 if no requests have been made.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use cloud_wallet_kms::cache::CacheStats;
    /// let stats = CacheStats {
    ///     hits: 75,
    ///     misses: 25,
    ///     evictions: 10,
    /// };
    /// assert_eq!(stats.hit_rate(), 0.75);
    /// ```
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    /// Returns the total number of cache requests (hits + misses).
    pub fn total_requests(&self) -> u64 {
        self.hits + self.misses
    }

    /// Returns the total number of evictions.
    pub fn total_evictions(&self) -> u64 {
        self.evictions
    }
}

impl fmt::Display for CacheStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CacheStats {{ hits: {}, misses: {}, evictions: {} }}",
            self.hits, self.misses, self.evictions
        )
    }
}
