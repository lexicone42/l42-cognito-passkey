//! DynamoDB entity provider for production deployments.
//!
//! Entity table schema:
//! - `id` (S) — partition key, the resource identifier (e.g. "doc-123")
//! - `owner` (S) — Cognito sub of the resource owner
//!
//! Deployers populate this table when resources are created, updated,
//! or transferred. The authorize endpoint queries it to verify ownership
//! instead of trusting client-provided `resource.owner`.

use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::AttributeValue;

use super::{EntityLookupError, EntityProvider};

/// DynamoDB-backed entity ownership provider.
pub struct DynamoDbEntityProvider {
    client: Client,
    table_name: String,
}

impl DynamoDbEntityProvider {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

impl EntityProvider for DynamoDbEntityProvider {
    async fn get_resource_owner(
        &self,
        resource_id: &str,
    ) -> Result<Option<String>, EntityLookupError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("id", AttributeValue::S(resource_id.to_string()))
            .projection_expression("owner")
            .send()
            .await
            .map_err(|e| EntityLookupError(format!("DynamoDB GetItem failed: {e}")))?;

        Ok(result
            .item()
            .and_then(|item| item.get("owner"))
            .and_then(|v| v.as_s().ok())
            .map(|s| s.to_string()))
    }
}
