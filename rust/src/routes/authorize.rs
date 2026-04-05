//! POST /auth/authorize

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use std::sync::Arc;

use crate::cognito::jwt::{decode_jwt_unverified, is_token_expired};
use crate::entity::EntityProvider;
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
    let claims =
        decode_jwt_unverified(&tokens.id_token).map_err(|_| AppError::TokenDecodeFailed)?;

    // Resolve resource ownership via entity provider (closes S1 gap).
    // When an entity provider is configured, the server-side owner overrides
    // whatever the client sent — preventing the ownership-spoofing attack.
    let resolved_resource = match (&state.entity_provider, &body.resource) {
        (Some(provider), Some(res)) if res.id.is_some() => {
            let id = res.id.as_deref().unwrap();
            let mut resolved = res.clone();
            match provider.get_resource_owner(id).await {
                Ok(Some(true_owner)) => {
                    if res.owner.is_some() && res.owner.as_deref() != Some(&true_owner) {
                        tracing::warn!(
                            resource_id = %id,
                            client_owner = ?res.owner,
                            true_owner = %true_owner,
                            "Client-supplied resource owner overridden by entity provider"
                        );
                    }
                    resolved.owner = Some(true_owner);
                }
                Ok(None) => {
                    // Resource not in entity store — remove client-provided owner
                    // (no ownership enforcement for untracked resources)
                    resolved.owner = None;
                }
                Err(e) => {
                    tracing::error!(resource_id = %id, error = %e, "Entity lookup failed");
                    // Fail-closed: remove untrusted client-provided owner
                    resolved.owner = None;
                }
            }
            Some(resolved)
        }
        _ => body.resource.clone(),
    };

    // Convert resource for OCSF (logs the original client request, not the resolved value)
    let resource_json = body
        .resource
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap());

    // Evaluate with resolved resource
    match cedar.authorize(&claims, &body.action, resolved_resource.as_ref(), None) {
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
