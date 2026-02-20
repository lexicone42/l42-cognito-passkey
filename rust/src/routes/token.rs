//! GET /auth/token

use axum::Json;

use crate::cognito::jwt::is_token_expired;
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, TokenResponse};

/// Return access + id tokens from session (never the refresh token).
pub async fn get_token(session: SessionHandle) -> Result<Json<TokenResponse>, AppError> {
    let data = session.data.lock().await;
    let tokens: SessionTokens = data
        .get("tokens")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(AppError::NotAuthenticated)?;

    let email = ocsf::email_from_session(Some(&tokens));

    if is_token_expired(&tokens.id_token) {
        ocsf::authentication_event(
            ocsf::ACTIVITY_OTHER,
            "Other",
            ocsf::STATUS_FAILURE,
            ocsf::SEVERITY_MEDIUM,
            email.as_deref(),
            ocsf::AUTH_PROTOCOL_OAUTH2,
            "OAuth 2.0/OIDC",
            "Token retrieval failed: token expired",
        );
        return Err(AppError::TokenExpired);
    }

    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        auth_method: tokens.auth_method.unwrap_or_else(|| "handler".into()),
    }))
}
