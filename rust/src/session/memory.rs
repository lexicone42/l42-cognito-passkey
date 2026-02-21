//! In-memory session backend for development and testing.
//!
//! Uses `DashMap` for concurrent access without external locks.
//! Sessions expire after `max_age` seconds (default: 30 days).

use dashmap::DashMap;
use std::time::{Duration, Instant};

use super::{SessionBackend, SessionData};

/// In-memory session store.
///
/// Not suitable for production — sessions are lost on restart and not
/// shared across processes. Use DynamoDB backend for production.
pub struct InMemoryBackend {
    store: DashMap<String, (SessionData, Instant)>,
    max_age: Duration,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::with_max_age(Duration::from_secs(30 * 24 * 3600))
    }

    pub fn with_max_age(max_age: Duration) -> Self {
        Self {
            store: DashMap::new(),
            max_age,
        }
    }

    /// Number of sessions currently stored (including expired).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the store is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBackend for InMemoryBackend {
    async fn load(&self, session_id: &str) -> Option<SessionData> {
        let entry = self.store.get(session_id)?;
        let (data, created) = entry.value();

        if created.elapsed() > self.max_age {
            drop(entry); // Release the read lock before removing
            self.store.remove(session_id);
            return None;
        }

        Some(data.clone())
    }

    async fn save(&self, session_id: &str, data: &SessionData) {
        let created = self
            .store
            .get(session_id)
            .map(|e| e.value().1)
            .unwrap_or_else(Instant::now);

        self.store
            .insert(session_id.to_string(), (data.clone(), created));
    }

    async fn delete(&self, session_id: &str) {
        self.store.remove(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_save_and_load() {
        let backend = InMemoryBackend::new();
        let mut data = SessionData::new();
        data.set("key", serde_json::json!("value"));

        backend.save("s1", &data).await;
        let loaded = backend.load("s1").await;

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().get("key").unwrap(), "value");
    }

    #[tokio::test]
    async fn test_load_nonexistent() {
        let backend = InMemoryBackend::new();
        assert!(backend.load("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_delete() {
        let backend = InMemoryBackend::new();
        let data = SessionData::new();

        backend.save("s1", &data).await;
        assert!(backend.load("s1").await.is_some());

        backend.delete("s1").await;
        assert!(backend.load("s1").await.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_is_noop() {
        let backend = InMemoryBackend::new();
        backend.delete("nonexistent").await; // Should not panic
    }

    #[tokio::test]
    async fn test_update_preserves_creation_time() {
        let backend = InMemoryBackend::new();
        let mut data = SessionData::new();
        data.set("v", serde_json::json!(1));

        backend.save("s1", &data).await;
        let created1 = backend.store.get("s1").unwrap().value().1;

        // Update the data
        data.set("v", serde_json::json!(2));
        backend.save("s1", &data).await;
        let created2 = backend.store.get("s1").unwrap().value().1;

        // Creation time should be preserved
        assert_eq!(created1, created2);

        // But data should be updated
        let loaded = backend.load("s1").await.unwrap();
        assert_eq!(loaded.get("v").unwrap(), 2);
    }

    #[tokio::test]
    async fn test_expiry() {
        // Create backend with 0-second TTL (everything expires immediately)
        let backend = InMemoryBackend::with_max_age(Duration::from_secs(0));
        let data = SessionData::new();

        backend.save("s1", &data).await;

        // Tiny sleep to ensure the instant has elapsed
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert!(backend.load("s1").await.is_none());
        // Expired entry should be removed from store
        assert_eq!(backend.len(), 0);
    }

    #[tokio::test]
    async fn test_multiple_sessions_isolated() {
        let backend = InMemoryBackend::new();
        let mut data_a = SessionData::new();
        data_a.set("user", serde_json::json!("alice"));
        let mut data_b = SessionData::new();
        data_b.set("user", serde_json::json!("bob"));

        backend.save("session-a", &data_a).await;
        backend.save("session-b", &data_b).await;

        assert_eq!(
            backend
                .load("session-a")
                .await
                .unwrap()
                .get("user")
                .unwrap(),
            "alice"
        );
        assert_eq!(
            backend
                .load("session-b")
                .await
                .unwrap()
                .get("user")
                .unwrap(),
            "bob"
        );

        // Deleting one doesn't affect the other
        backend.delete("session-a").await;
        assert!(backend.load("session-a").await.is_none());
        assert!(backend.load("session-b").await.is_some());
    }
}
