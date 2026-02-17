//! OCSF (Open Cybersecurity Schema Framework) structured event logging.
//!
//! Mirrors `app/ocsf.py`. Events are emitted via `tracing::info!` as
//! structured JSON. Never panics — errors are silently caught.

use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

// OCSF event class UIDs
pub const CLASS_AUTHENTICATION: u32 = 3001;

// Activity IDs
pub const ACTIVITY_LOGON: u32 = 1;
pub const ACTIVITY_LOGOFF: u32 = 2;
pub const ACTIVITY_AUTH_TICKET: u32 = 3; // OAuth token exchange
pub const ACTIVITY_SERVICE_TICKET: u32 = 4; // Token refresh
pub const ACTIVITY_OTHER: u32 = 99; // Authorization decisions

// Status IDs
pub const STATUS_SUCCESS: u32 = 1;
pub const STATUS_FAILURE: u32 = 2;

// Severity IDs
pub const SEVERITY_INFORMATIONAL: u32 = 1;
pub const SEVERITY_LOW: u32 = 2;
pub const SEVERITY_MEDIUM: u32 = 3;
pub const SEVERITY_HIGH: u32 = 4;

// Auth protocol IDs
pub const AUTH_PROTOCOL_UNKNOWN: u32 = 0;
pub const AUTH_PROTOCOL_PASSWORD: u32 = 2;
pub const AUTH_PROTOCOL_OAUTH2: u32 = 10;
pub const AUTH_PROTOCOL_FIDO2: u32 = 99;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn severity_name(id: u32) -> &'static str {
    match id {
        SEVERITY_INFORMATIONAL => "Informational",
        SEVERITY_LOW => "Low",
        SEVERITY_MEDIUM => "Medium",
        SEVERITY_HIGH => "High",
        5 => "Critical",
        _ => "Unknown",
    }
}

fn status_name(id: u32) -> &'static str {
    match id {
        STATUS_SUCCESS => "Success",
        _ => "Failure",
    }
}

/// Emit an OCSF event as structured JSON via tracing. Never panics.
fn emit(event: &serde_json::Value) {
    if let Ok(json) = serde_json::to_string(event) {
        tracing::info!(target: "ocsf", "{}", json);
    }
}

/// Emit an OCSF Authentication (3001) event.
#[allow(clippy::too_many_arguments)]
pub fn authentication_event(
    activity_id: u32,
    activity_name: &str,
    status_id: u32,
    severity_id: u32,
    user_email: Option<&str>,
    auth_protocol_id: u32,
    auth_protocol: &str,
    message: &str,
) {
    let mut event = json!({
        "class_uid": CLASS_AUTHENTICATION,
        "class_name": "Authentication",
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": severity_id,
        "severity": severity_name(severity_id),
        "status_id": status_id,
        "status": status_name(status_id),
        "time": now_millis(),
        "metadata": {
            "product": {
                "name": "l42-token-handler-rust",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor_name": "L42"
            }
        },
        "auth_protocol_id": auth_protocol_id,
        "auth_protocol": auth_protocol,
        "message": message,
    });

    if let Some(email) = user_email {
        event["actor"] = json!({
            "user": {
                "email_addr": email,
                "type_id": 1,
                "type": "User"
            }
        });
    }

    emit(&event);
}

/// Emit an OCSF Authorization event (class 3001, activity 99/Other).
pub fn authorization_event(
    action: &str,
    resource: Option<&serde_json::Value>,
    decision: &str,
    reason: &str,
    severity_id: u32,
    user_email: Option<&str>,
) {
    let status_id = if decision == "permit" {
        STATUS_SUCCESS
    } else {
        STATUS_FAILURE
    };

    let mut event = json!({
        "class_uid": CLASS_AUTHENTICATION,
        "class_name": "Authentication",
        "activity_id": ACTIVITY_OTHER,
        "activity_name": "Other",
        "severity_id": severity_id,
        "severity": severity_name(severity_id),
        "status_id": status_id,
        "status": status_name(status_id),
        "time": now_millis(),
        "metadata": {
            "product": {
                "name": "l42-token-handler-rust",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor_name": "L42"
            },
            "authorization": {
                "action": action,
                "resource": resource.unwrap_or(&json!({})),
                "decision": decision,
                "reason": reason,
            }
        },
        "message": format!("Cedar authorization: {} for {}", decision, action),
    });

    if let Some(email) = user_email {
        event["actor"] = json!({
            "user": {
                "email_addr": email,
                "type_id": 1,
                "type": "User"
            }
        });
    }

    emit(&event);
}

/// Determine auth protocol from auth_method string.
pub fn auth_protocol_from_method(method: &str) -> (u32, &'static str) {
    match method {
        "passkey" => (AUTH_PROTOCOL_FIDO2, "FIDO2/Passkey"),
        "password" => (AUTH_PROTOCOL_PASSWORD, "Password"),
        "oauth" => (AUTH_PROTOCOL_OAUTH2, "OAuth 2.0/OIDC"),
        _ => (AUTH_PROTOCOL_UNKNOWN, "Unknown"),
    }
}

/// Extract email from session tokens (best-effort).
pub fn email_from_session(tokens: Option<&crate::types::SessionTokens>) -> Option<String> {
    let tokens = tokens?;
    let claims = crate::cognito::jwt::decode_jwt_unverified(&tokens.id_token).ok()?;
    claims.email
}
