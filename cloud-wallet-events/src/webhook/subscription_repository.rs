use crate::webhook::subscription::WebhookSubscription;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Async repository for [`WebhookSubscription`] storage and retrieval.
///
/// The library depends only on this trait. Callers provide the concrete
/// implementation — in-memory for tests and simple deployments, or
/// database-backed for production.
///
/// # Implementor contract
///
/// - [`find_for_event`] must return every subscription whose `event_types`
///   set matches the given `event_type`, as well as any catch-all
///   subscriptions (those with an empty `event_types` set).
/// - All methods must be safe to call concurrently from multiple tasks.
#[async_trait::async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Return all subscriptions that should receive the given event type.
    async fn find_for_event(&self, event_type: &str) -> Vec<WebhookSubscription>;

    /// Return the subscription with the given `id`, if it exists.
    async fn find_by_id(&self, id: &str) -> Option<WebhookSubscription>;

    /// Persist a new subscription (or overwrite an existing one with the same id).
    async fn upsert(&self, subscription: WebhookSubscription);

    /// Remove the subscription with the given `id`. Returns `true` if it existed.
    async fn remove(&self, id: &str) -> bool;
}

/// In-memory [`SubscriptionRepository`] with O(1) event-type fan-out.
///
/// Subscriptions are indexed in two structures:
///
/// - `by_event_type` — a `HashMap<event_type, Vec<id>>` that maps each
///   distinct event type string to the IDs of subscriptions that want it.
/// - `catch_all` — IDs of subscriptions with an empty `event_types` set
///   (i.e. those that receive every event).
/// - `store` — the authoritative `HashMap<id, WebhookSubscription>` from
///   which full subscription data is retrieved.
///
/// `find_for_event` is O(k) where k is the number of matching subscriptions,
/// avoiding a full scan of all subscriptions on every event.
#[derive(Debug, Default)]
pub struct InMemorySubscriptionRepository {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Authoritative subscription store keyed by subscription id.
    store: HashMap<String, WebhookSubscription>,
    /// event_type → subscription ids.
    by_event_type: HashMap<String, Vec<String>>,
    /// Subscription ids that receive all events (empty event_types set).
    catch_all: Vec<String>,
}

impl InMemorySubscriptionRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl SubscriptionRepository for InMemorySubscriptionRepository {
    async fn find_for_event(&self, event_type: &str) -> Vec<WebhookSubscription> {
        let inner = self.inner.read().await;

        // Collect IDs: event-specific subscriptions + catch-all subscriptions.
        let specific = inner
            .by_event_type
            .get(event_type)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        specific
            .iter()
            .chain(inner.catch_all.iter())
            .filter_map(|id| inner.store.get(id).cloned())
            .collect()
    }

    async fn find_by_id(&self, id: &str) -> Option<WebhookSubscription> {
        self.inner.read().await.store.get(id).cloned()
    }

    async fn upsert(&self, subscription: WebhookSubscription) {
        let mut inner = self.inner.write().await;

        // Remove stale index entries for this id before re-indexing.
        remove_from_index(&mut inner, &subscription.id);

        // Re-index.
        if subscription.event_types.is_empty() {
            inner.catch_all.push(subscription.id.clone());
        } else {
            for event_type in &subscription.event_types {
                inner
                    .by_event_type
                    .entry(event_type.clone())
                    .or_default()
                    .push(subscription.id.clone());
            }
        }

        inner.store.insert(subscription.id.clone(), subscription);
    }

    async fn remove(&self, id: &str) -> bool {
        let mut inner = self.inner.write().await;
        if inner.store.remove(id).is_none() {
            return false;
        }
        remove_from_index(&mut inner, id);
        true
    }
}

/// Remove all index entries for `id` without touching the authoritative store.
fn remove_from_index(inner: &mut Inner, id: &str) {
    inner.catch_all.retain(|s| s != id);
    for ids in inner.by_event_type.values_mut() {
        ids.retain(|s| s != id);
    }
    // Prune empty vecs to keep the map tidy.
    inner.by_event_type.retain(|_, ids| !ids.is_empty());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::subscription::{WebhookAuth, WebhookSubscription};

    fn sub(id: &str, event_types: Vec<&str>) -> WebhookSubscription {
        WebhookSubscription::new(id, format!("https://example.com/{id}"), WebhookAuth::None)
            .unwrap()
            .subscribe_to(event_types)
    }

    fn sub_all(id: &str) -> WebhookSubscription {
        WebhookSubscription::new(id, format!("https://example.com/{id}"), WebhookAuth::None)
            .unwrap()
            .subscribe_all()
    }

    #[tokio::test]
    async fn test_find_for_specific_event_type() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("s1", vec!["credential.stored"])).await;
        repo.upsert(sub("s2", vec!["key.created"])).await;

        let results = repo.find_for_event("credential.stored").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "s1");
    }

    #[tokio::test]
    async fn test_catch_all_subscriptions_included_in_every_event() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("specific", vec!["credential.stored"]))
            .await;
        repo.upsert(sub_all("wildcard")).await;

        let results = repo.find_for_event("credential.stored").await;
        let ids: Vec<_> = results.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"specific"));
        assert!(ids.contains(&"wildcard"));

        // Wildcard also appears for an event the specific sub doesn't match.
        let results2 = repo.find_for_event("unrelated.event").await;
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].id, "wildcard");
    }

    #[tokio::test]
    async fn test_find_by_id() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("s1", vec!["x"])).await;

        assert!(repo.find_by_id("s1").await.is_some());
        assert!(repo.find_by_id("missing").await.is_none());
    }

    #[tokio::test]
    async fn test_remove_cleans_up_index() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("s1", vec!["credential.stored"])).await;
        assert!(repo.remove("s1").await);
        assert!(repo.find_for_event("credential.stored").await.is_empty());
        assert!(!repo.remove("s1").await); // idempotent — second remove returns false
    }

    #[tokio::test]
    async fn test_upsert_replaces_existing() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("s1", vec!["event.a"])).await;
        // Re-upsert with different event type.
        repo.upsert(sub("s1", vec!["event.b"])).await;

        assert!(repo.find_for_event("event.a").await.is_empty());
        assert_eq!(repo.find_for_event("event.b").await.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_subscriptions_same_event_type() {
        let repo = InMemorySubscriptionRepository::new();
        repo.upsert(sub("s1", vec!["credential.stored"])).await;
        repo.upsert(sub("s2", vec!["credential.stored"])).await;

        let results = repo.find_for_event("credential.stored").await;
        assert_eq!(results.len(), 2);
    }
}
