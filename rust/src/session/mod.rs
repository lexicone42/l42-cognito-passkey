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

/// A session persistence failure (write/delete). Mirrors `EntityLookupError`.
///
/// The middleware turns a save failure into a 500 *without* a `Set-Cookie`, and
/// a delete failure into a 500 that still clears the browser cookie — so a
/// failed persist can never masquerade as a successful login/logout.
#[derive(Debug, thiserror::Error)]
#[error("Session store error: {0}")]
pub struct SessionError(pub String);

// We can't use the async_trait crate macro directly on a trait definition
// inside a module without the dependency, so we define the trait with
// standard async fn in trait (stabilized in Rust 1.75).

/// Pluggable session storage backend.
///
/// Implementations must be `Send + Sync` for use in Axum's async handlers.
///
/// `save`/`delete` return `Result` so a fallible backend (DynamoDB) can report
/// a persistence failure instead of silently swallowing it — the middleware
/// depends on this to avoid setting a session cookie for a session that was
/// never actually written.
pub trait SessionBackend: Send + Sync {
    /// Load session data by ID. Returns `None` if not found or expired.
    fn load(
        &self,
        session_id: &str,
    ) -> impl std::future::Future<Output = Option<SessionData>> + Send;

    /// Save session data. `Err` means the write did not durably persist.
    fn save(
        &self,
        session_id: &str,
        data: &SessionData,
    ) -> impl std::future::Future<Output = Result<(), SessionError>> + Send;

    /// Delete a session. `Err` means the record may still exist server-side.
    fn delete(
        &self,
        session_id: &str,
    ) -> impl std::future::Future<Output = Result<(), SessionError>> + Send;
}

/// Type-erased session backend supporting both InMemory and DynamoDB.
///
/// Since `SessionBackend` uses RPITIT, it's not object-safe. This enum
/// dispatches manually instead.
pub enum AnyBackend {
    Memory(memory::InMemoryBackend),
    DynamoDb(dynamodb::DynamoDbBackend),
    /// Test double whose writes always fail — used by integration tests to
    /// exercise the middleware's persistence-failure path. Not for production.
    #[doc(hidden)]
    Failing(memory::FailingBackend),
}

impl SessionBackend for AnyBackend {
    async fn load(&self, session_id: &str) -> Option<SessionData> {
        match self {
            AnyBackend::Memory(b) => b.load(session_id).await,
            AnyBackend::DynamoDb(b) => b.load(session_id).await,
            AnyBackend::Failing(b) => b.load(session_id).await,
        }
    }

    async fn save(&self, session_id: &str, data: &SessionData) -> Result<(), SessionError> {
        match self {
            AnyBackend::Memory(b) => b.save(session_id, data).await,
            AnyBackend::DynamoDb(b) => b.save(session_id, data).await,
            AnyBackend::Failing(b) => b.save(session_id, data).await,
        }
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionError> {
        match self {
            AnyBackend::Memory(b) => b.delete(session_id).await,
            AnyBackend::DynamoDb(b) => b.delete(session_id).await,
            AnyBackend::Failing(b) => b.delete(session_id).await,
        }
    }
}
