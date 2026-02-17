//! GET /auth/me

use axum::Json;

use crate::cognito::jwt::decode_jwt_unverified;
use crate::error::AppError;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, UserInfoResponse};

/// Return user info decoded from the session's ID token (unverified).
pub async fn me(session: SessionHandle) -> Result<Json<UserInfoResponse>, AppError> {
    let data = session.data.lock().await;
    let tokens: SessionTokens = data
        .get("tokens")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(AppError::NotAuthenticated)?;

    let claims = decode_jwt_unverified(&tokens.id_token).map_err(|_| AppError::TokenDecodeFailed)?;

    Ok(Json(UserInfoResponse {
        email: claims.email,
        sub: Some(claims.sub),
        groups: claims.cognito_groups,
    }))
}
