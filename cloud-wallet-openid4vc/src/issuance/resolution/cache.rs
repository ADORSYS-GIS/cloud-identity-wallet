//! Metadata caching utilities.
//!
//! Provides cache key generation and utilities for storing issuer and
//! authorization server metadata with configurable TTL.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// Default cache TTL in seconds (5 minutes).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Default maximum cache capacity.
pub const DEFAULT_MAX_CAPACITY: u64 = 1000;

/// SHA-256 hash of a URL string, hex-encoded.
pub fn url_hash(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Cache key for issuer metadata.
pub fn issuer_cache_key(issuer_url: &str) -> String {
    format!("issuer:{}", url_hash(issuer_url))
}

/// Cache key for authorization server metadata.
pub fn as_cache_key(as_url: &str) -> String {
    format!("as:{}", url_hash(as_url))
}

/// A typed metadata cache using cloud-wallet-kms::cache::Cache.
///
/// This is a thin wrapper that provides metadata-specific caching with
/// TTL-based expiration.
pub type MetadataCache<V> = cloud_wallet_kms::cache::Cache<String, V>;

/// Creates a new metadata cache with the given TTL and capacity.
pub fn create_cache<V>(ttl: Duration, max_capacity: u64) -> MetadataCache<V>
where
    V: Clone + Send + Sync + 'static,
{
    MetadataCache::builder()
        .max_capacity(max_capacity)
        .time_to_live(ttl)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_hash_is_consistent() {
        let url = "https://issuer.example.com";
        let hash1 = url_hash(url);
        let hash2 = url_hash(url);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn url_hash_differs_for_different_urls() {
        let hash1 = url_hash("https://issuer1.example.com");
        let hash2 = url_hash("https://issuer2.example.com");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn cache_key_formats_correctly() {
        let key = issuer_cache_key("https://issuer.example.com");
        assert!(key.starts_with("issuer:"));
        assert!(key.len() > "issuer:".len());
    }

    #[tokio::test]
    async fn cache_stores_and_retrieves() {
        let cache: MetadataCache<String> = create_cache(Duration::from_secs(60), 100);

        cache.insert("key".to_string(), "value".to_string()).await;
        let result = cache.get(&"key".to_string()).await;
        assert_eq!(result, Some("value".to_string()));
    }

    #[tokio::test]
    async fn cache_returns_none_for_missing_key() {
        let cache: MetadataCache<String> = create_cache(Duration::from_secs(60), 100);
        let result = cache.get(&"missing".to_string()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_removes_entry() {
        let cache: MetadataCache<String> = create_cache(Duration::from_secs(60), 100);

        cache.insert("key".to_string(), "value".to_string()).await;
        let removed = cache.remove(&"key".to_string()).await;
        assert_eq!(removed, Some("value".to_string()));

        let result = cache.get(&"key".to_string()).await;
        assert!(result.is_none());
    }
}
