//! DynamoDB session backend for production/Lambda deployments.
//!
//! Same table schema as the FastAPI backend:
//! - `session_id` (S) — partition key
//! - `data` (S) — JSON-encoded session payload
//! - `created_at` (N) — Unix timestamp when session was created
//! - `ttl` (N) — Unix timestamp for DynamoDB automatic cleanup
//!
//! Compatible with existing FastAPI DynamoDB sessions table.

use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{SessionBackend, SessionData};

const MAX_AGE_SECS: u64 = 30 * 24 * 3600; // 30 days

/// DynamoDB session backend.
pub struct DynamoDbBackend {
    client: Client,
    table_name: String,
}

impl DynamoDbBackend {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SessionBackend for DynamoDbBackend {
    async fn load(&self, session_id: &str) -> Option<SessionData> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .send()
            .await
            .ok()?;

        let item = result.item()?;

        // Check application-level TTL (in case DynamoDB hasn't cleaned up yet)
        let created_at = item
            .get("created_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);

        let now = now_secs();
        if now.saturating_sub(created_at) > MAX_AGE_SECS {
            // Expired — delete and return None
            let _ = self
                .client
                .delete_item()
                .table_name(&self.table_name)
                .key("session_id", AttributeValue::S(session_id.to_string()))
                .send()
                .await;
            return None;
        }

        // Deserialize session data from JSON string
        let data_json = item.get("data")?.as_s().ok()?;
        serde_json::from_str(data_json).ok()
    }

    async fn save(&self, session_id: &str, data: &SessionData) {
        let now = now_secs();
        let ttl = now + MAX_AGE_SECS;
        let data_json = match serde_json::to_string(data) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("Failed to serialize session data: {}", e);
                return;
            }
        };

        // Use UpdateItem with if_not_exists to preserve original created_at.
        // PutItem would overwrite created_at on every save, making the 30-day
        // TTL reset on each write (effectively "30 days since last activity"
        // instead of "30 days since creation").
        let _ = self
            .client
            .update_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .update_expression(
                "SET #data = :data, created_at = if_not_exists(created_at, :now), #ttl = :ttl",
            )
            .expression_attribute_names("#data", "data")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":data", AttributeValue::S(data_json))
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .expression_attribute_values(":ttl", AttributeValue::N(ttl.to_string()))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to save session {}: {}", session_id, e);
            });
    }

    async fn delete(&self, session_id: &str) {
        let _ = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .key("session_id", AttributeValue::S(session_id.to_string()))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete session {}: {}", session_id, e);
            });
    }
}
