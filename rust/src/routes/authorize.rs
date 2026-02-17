//! POST /auth/authorize

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;

use crate::cognito::jwt::{decode_jwt_unverified, is_token_expired};
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{AuthorizeRequest, AuthorizeResponse, SessionTokens};

/// Cedar authorization evaluation.
pub async fn authorize(
    State(state): State<Arc<crate::AppState>>,
    session: SessionHandle,
    Json(body): Json<AuthorizeRequest>,
) -> Result<(StatusCode, Json<AuthorizeResponse>), AppError> {
    // Validate action
    if body.action.is_empty() {
        return Err(AppError::BadRequest("Missing or invalid action".into()));
    }

    // Get tokens from session
    let tokens: SessionTokens = {
        let data = session.data.lock().await;
        data.get("tokens")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(AppError::NotAuthenticated)?
    };

    // Check expiry
    if is_token_expired(&tokens.id_token) {
        return Err(AppError::TokenExpired);
    }

    // Email for OCSF
    let email = decode_jwt_unverified(&tokens.id_token)
        .ok()
        .and_then(|c| c.email.clone());

    // Check Cedar is initialized
    let cedar = match &state.cedar {
        Some(c) => c,
        None => {
            ocsf::authorization_event(
                &body.action,
                None,
                "error",
                "Cedar engine not initialized",
                ocsf::SEVERITY_HIGH,
                email.as_deref(),
            );
            return Err(AppError::CedarUnavailable);
        }
    };

    // Decode claims for Cedar evaluation
    let claims = decode_jwt_unverified(&tokens.id_token).map_err(|_| AppError::TokenDecodeFailed)?;

    // Convert resource for OCSF
    let resource_json = body
        .resource
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap());

    // Evaluate
    match cedar.authorize(&claims, &body.action, body.resource.as_ref(), None) {
        Ok(result) => {
            let decision = if result.authorized { "permit" } else { "deny" };
            let severity = if result.authorized {
                ocsf::SEVERITY_INFORMATIONAL
            } else {
                ocsf::SEVERITY_MEDIUM
            };

            ocsf::authorization_event(
                &body.action,
                resource_json.as_ref(),
                decision,
                &result.reason,
                severity,
                email.as_deref(),
            );

            let status = if result.authorized {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };

            Ok((
                status,
                Json(AuthorizeResponse {
                    authorized: result.authorized,
                    reason: result.reason,
                    diagnostics: Some(serde_json::json!({})),
                    error: None,
                }),
            ))
        }
        Err(e) => {
            ocsf::authorization_event(
                &body.action,
                resource_json.as_ref(),
                "error",
                &e.to_string(),
                ocsf::SEVERITY_HIGH,
                email.as_deref(),
            );
            Err(AppError::AuthorizationError(e.to_string()))
        }
    }
}
