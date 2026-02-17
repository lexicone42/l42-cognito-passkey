//! GET /auth/token

use axum::Json;

use crate::cognito::jwt::is_token_expired;
use crate::error::AppError;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, TokenResponse};

/// Return access + id tokens from session (never the refresh token).
pub async fn get_token(session: SessionHandle) -> Result<Json<TokenResponse>, AppError> {
    let data = session.data.lock().await;
    let tokens: SessionTokens = data
        .get("tokens")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(AppError::NotAuthenticated)?;

    if is_token_expired(&tokens.id_token) {
        return Err(AppError::TokenExpired);
    }

    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        auth_method: tokens.auth_method.unwrap_or_else(|| "handler".into()),
    }))
}
