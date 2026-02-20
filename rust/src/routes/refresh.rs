//! POST /auth/refresh

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::cognito::client;
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, TokenResponse};

/// Refresh tokens via Cognito, update session.
pub async fn refresh_tokens(
    State(state): State<Arc<crate::AppState>>,
    session: SessionHandle,
) -> Result<Json<TokenResponse>, AppError> {
    let tokens: SessionTokens = {
        let data = session.data.lock().await;
        data.get("tokens")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .ok_or(AppError::NotAuthenticated)?
    };

    let refresh_token = tokens
        .refresh_token
        .as_deref()
        .ok_or(AppError::NoRefreshToken)?;

    let email = crate::cognito::jwt::decode_jwt_unverified(&tokens.id_token)
        .ok()
        .and_then(|c| c.email);

    // Call Cognito to refresh
    match client::refresh_tokens(&state.http_client, &state.config, refresh_token).await {
        Ok(result) => {
            let auth_result = result.get("AuthenticationResult");
            let new_access = auth_result
                .and_then(|r| r.get("AccessToken"))
                .and_then(|v| v.as_str());
            let new_id = auth_result
                .and_then(|r| r.get("IdToken"))
                .and_then(|v| v.as_str());

            match (new_access, new_id) {
                (Some(at), Some(it)) => {
                    // Use rotated refresh token if Cognito returned one, else keep existing
                    let new_refresh = auth_result
                        .and_then(|r| r.get("RefreshToken"))
                        .and_then(|v| v.as_str())
                        .map(|rt| Some(rt.to_string()))
                        .unwrap_or_else(|| tokens.refresh_token.clone());

                    let new_tokens = SessionTokens {
                        access_token: at.to_string(),
                        id_token: it.to_string(),
                        refresh_token: new_refresh,
                        auth_method: tokens.auth_method.clone(),
                    };

                    let mut data = session.data.lock().await;
                    data.set("tokens", serde_json::to_value(&new_tokens).unwrap());

                    ocsf::authentication_event(
                        ocsf::ACTIVITY_SERVICE_TICKET,
                        "Service Ticket",
                        ocsf::STATUS_SUCCESS,
                        ocsf::SEVERITY_INFORMATIONAL,
                        email.as_deref(),
                        ocsf::AUTH_PROTOCOL_OAUTH2,
                        "OAuth 2.0/OIDC",
                        "Token refresh succeeded",
                    );

                    Ok(Json(TokenResponse {
                        access_token: new_tokens.access_token,
                        id_token: new_tokens.id_token,
                        auth_method: new_tokens
                            .auth_method
                            .unwrap_or_else(|| "handler".into()),
                    }))
                }
                _ => {
                    // Cognito returned success but no tokens — shouldn't happen
                    Err(AppError::Internal("Refresh failed".into()))
                }
            }
        }
        Err(e) => {
            // Refresh failed — destroy session (Token Handler protocol invariant #6)
            ocsf::authentication_event(
                ocsf::ACTIVITY_SERVICE_TICKET,
                "Service Ticket",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_MEDIUM,
                email.as_deref(),
                ocsf::AUTH_PROTOCOL_OAUTH2,
                "OAuth 2.0/OIDC",
                &format!("Token refresh failed: {}", e),
            );

            let mut destroyed = session.destroyed.lock().await;
            *destroyed = true;
            let mut data = session.data.lock().await;
            data.clear();

            Err(AppError::RefreshFailed(e.to_string()))
        }
    }
}
