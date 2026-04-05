//! In-memory entity provider for development and testing.

use dashmap::DashMap;

use super::{EntityLookupError, EntityProvider};

/// In-memory entity provider backed by DashMap.
pub struct InMemoryEntityProvider {
    owners: DashMap<String, String>,
}

impl Default for InMemoryEntityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEntityProvider {
    pub fn new() -> Self {
        Self {
            owners: DashMap::new(),
        }
    }

    /// Register a resource's owner (Cognito sub).
    pub fn set_owner(&self, resource_id: &str, owner: &str) {
        self.owners.insert(resource_id.into(), owner.into());
    }
}

impl EntityProvider for InMemoryEntityProvider {
    async fn get_resource_owner(
        &self,
        resource_id: &str,
    ) -> Result<Option<String>, EntityLookupError> {
        Ok(self.owners.get(resource_id).map(|v| v.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get_owner() {
        let provider = InMemoryEntityProvider::new();
        provider.set_owner("doc-1", "user-123");

        let owner = provider.get_resource_owner("doc-1").await.unwrap();
        assert_eq!(owner, Some("user-123".to_string()));
    }

    #[tokio::test]
    async fn test_not_found() {
        let provider = InMemoryEntityProvider::new();
        let owner = provider.get_resource_owner("nonexistent").await.unwrap();
        assert_eq!(owner, None);
    }

    #[tokio::test]
    async fn test_overwrite_owner() {
        let provider = InMemoryEntityProvider::new();
        provider.set_owner("doc-1", "user-a");
        provider.set_owner("doc-1", "user-b");

        let owner = provider.get_resource_owner("doc-1").await.unwrap();
        assert_eq!(owner, Some("user-b".to_string()));
    }
}
