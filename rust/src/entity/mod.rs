//! Resource entity provider for trusted ownership lookups.
//!
//! Closes the S1 security gap: instead of trusting client-provided
//! `resource.owner` in authorization requests, the server looks up the
//! true owner from a trusted data store.
//!
//! When an `EntityProvider` is configured, the `/auth/authorize` handler
//! queries it by resource ID and uses the server-side owner for Cedar
//! policy evaluation — ignoring whatever the client sent.

pub mod dynamodb;
pub mod memory;

/// Trait for looking up resource ownership from a trusted data store.
///
/// Implementations must be `Send + Sync` for use in Axum's async handlers.
pub trait EntityProvider: Send + Sync {
    /// Look up the owner (Cognito sub) of a resource by its ID.
    ///
    /// Returns `Ok(Some(owner_sub))` if found, `Ok(None)` if the resource
    /// is not tracked, or `Err` on backend failures.
    fn get_resource_owner(
        &self,
        resource_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<String>, EntityLookupError>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("Entity lookup failed: {0}")]
pub struct EntityLookupError(pub String);

/// Type-erased entity provider supporting multiple backends.
///
/// Uses the same enum dispatch pattern as `AnyBackend` for session storage,
/// because the `EntityProvider` trait uses RPITIT and isn't object-safe.
pub enum AnyEntityProvider {
    DynamoDb(dynamodb::DynamoDbEntityProvider),
    Memory(memory::InMemoryEntityProvider),
}

impl EntityProvider for AnyEntityProvider {
    async fn get_resource_owner(
        &self,
        resource_id: &str,
    ) -> Result<Option<String>, EntityLookupError> {
        match self {
            AnyEntityProvider::DynamoDb(p) => p.get_resource_owner(resource_id).await,
            AnyEntityProvider::Memory(p) => p.get_resource_owner(resource_id).await,
        }
    }
}
