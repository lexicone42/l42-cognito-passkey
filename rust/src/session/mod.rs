//! Server-side session management.
//!
//! Provides the `SessionBackend` trait for pluggable storage, HMAC-SHA256
//! cookie signing, and an in-memory backend for development/testing.

pub mod cookie;
pub mod dynamodb;
pub mod memory;
pub mod middleware;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Session data stored server-side.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SessionData {
    /// Flattened key-value store. The `tokens` key holds serialized `SessionTokens`.
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

impl SessionData {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    pub fn set(&mut self, key: &str, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    pub fn remove(&mut self, key: &str) {
        self.data.remove(key);
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// We can't use the async_trait crate macro directly on a trait definition
// inside a module without the dependency, so we define the trait with
// standard async fn in trait (stabilized in Rust 1.75).

/// Pluggable session storage backend.
///
/// Implementations must be `Send + Sync` for use in Axum's async handlers.
pub trait SessionBackend: Send + Sync {
    /// Load session data by ID. Returns `None` if not found or expired.
    fn load(
        &self,
        session_id: &str,
    ) -> impl std::future::Future<Output = Option<SessionData>> + Send;

    /// Save session data.
    fn save(
        &self,
        session_id: &str,
        data: &SessionData,
    ) -> impl std::future::Future<Output = ()> + Send;

    /// Delete a session.
    fn delete(&self, session_id: &str) -> impl std::future::Future<Output = ()> + Send;
}

/// Type-erased session backend supporting both InMemory and DynamoDB.
///
/// Since `SessionBackend` uses RPITIT, it's not object-safe. This enum
/// dispatches manually instead.
pub enum AnyBackend {
    Memory(memory::InMemoryBackend),
    DynamoDb(dynamodb::DynamoDbBackend),
}

impl SessionBackend for AnyBackend {
    async fn load(&self, session_id: &str) -> Option<SessionData> {
        match self {
            AnyBackend::Memory(b) => b.load(session_id).await,
            AnyBackend::DynamoDb(b) => b.load(session_id).await,
        }
    }

    async fn save(&self, session_id: &str, data: &SessionData) {
        match self {
            AnyBackend::Memory(b) => b.save(session_id, data).await,
            AnyBackend::DynamoDb(b) => b.save(session_id, data).await,
        }
    }

    async fn delete(&self, session_id: &str) {
        match self {
            AnyBackend::Memory(b) => b.delete(session_id).await,
            AnyBackend::DynamoDb(b) => b.delete(session_id).await,
        }
    }
}
