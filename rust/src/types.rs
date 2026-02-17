//! Shared request/response DTOs.
//!
//! These match the Pydantic models from the FastAPI routes exactly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// POST /auth/session request body.
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    #[serde(default = "default_auth_method")]
    pub auth_method: String,
}

fn default_auth_method() -> String {
    "direct".into()
}

/// POST /auth/authorize request body.
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub action: String,
    pub resource: Option<ResourceDescriptor>,
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Resource descriptor for Cedar authorization.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourceDescriptor {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub owner: Option<String>,
}

/// GET /auth/token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub auth_method: String,
}

/// POST /auth/authorize response.
#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorized: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// GET /health response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub mode: String,
    pub cedar: String,
}

/// GET /auth/me response.
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub email: Option<String>,
    pub sub: Option<String>,
    pub groups: Vec<String>,
}

/// Tokens stored in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub auth_method: Option<String>,
}

/// Generic success response.
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session_request_deserialization() {
        let json = r#"{
            "access_token": "at-123",
            "id_token": "it-456",
            "refresh_token": "rt-789",
            "auth_method": "passkey"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.access_token, "at-123");
        assert_eq!(req.id_token, "it-456");
        assert_eq!(req.refresh_token.as_deref(), Some("rt-789"));
        assert_eq!(req.auth_method, "passkey");
    }

    #[test]
    fn test_create_session_request_defaults() {
        let json = r#"{
            "access_token": "at",
            "id_token": "it"
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.auth_method, "direct");
        assert!(req.refresh_token.is_none());
    }

    #[test]
    fn test_authorize_request_minimal() {
        let json = r#"{"action": "read:content"}"#;
        let req: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, "read:content");
        assert!(req.resource.is_none());
        assert!(req.context.is_none());
    }

    #[test]
    fn test_authorize_request_full() {
        let json = r#"{
            "action": "write:own",
            "resource": {"id": "doc-1", "type": "document", "owner": "user-123"},
            "context": {"ip": "1.2.3.4"}
        }"#;
        let req: AuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, "write:own");
        let res = req.resource.unwrap();
        assert_eq!(res.id.as_deref(), Some("doc-1"));
        assert_eq!(res.resource_type.as_deref(), Some("document"));
        assert_eq!(res.owner.as_deref(), Some("user-123"));
    }

    #[test]
    fn test_token_response_serialization() {
        let resp = TokenResponse {
            access_token: "at".into(),
            id_token: "it".into(),
            auth_method: "passkey".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["access_token"], "at");
        assert_eq!(json["auth_method"], "passkey");
        // refresh_token must never appear in token response
        assert!(json.get("refresh_token").is_none());
    }

    #[test]
    fn test_authorize_response_skip_none() {
        let resp = AuthorizeResponse {
            authorized: true,
            reason: "allowed".into(),
            diagnostics: None,
            error: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("diagnostics").is_none());
        assert!(json.get("error").is_none());
    }

    #[test]
    fn test_session_tokens_roundtrip() {
        let tokens = SessionTokens {
            access_token: "at".into(),
            id_token: "it".into(),
            refresh_token: Some("rt".into()),
            auth_method: Some("passkey".into()),
        };
        let serialized = serde_json::to_string(&tokens).unwrap();
        let deserialized: SessionTokens = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.access_token, "at");
        assert_eq!(deserialized.refresh_token.as_deref(), Some("rt"));
    }

    #[test]
    fn test_resource_descriptor_partial() {
        let json = r#"{"id": "doc-1"}"#;
        let res: ResourceDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(res.id.as_deref(), Some("doc-1"));
        assert!(res.resource_type.is_none());
        assert!(res.owner.is_none());
    }

    #[test]
    fn test_health_response() {
        let resp = HealthResponse {
            status: "ok".into(),
            mode: "token-handler".into(),
            cedar: "ready".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["cedar"], "ready");
    }
}
