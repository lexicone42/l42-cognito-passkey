//! GET /auth/me

use axum::Json;

use crate::cognito::jwt::decode_jwt_unverified;
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, UserInfoResponse};

/// Return user info decoded from the session's ID token (unverified).
pub async fn me(session: SessionHandle) -> Result<Json<UserInfoResponse>, AppError> {
    let tokens: SessionTokens = session.tokens().await?;

    let claims = decode_jwt_unverified(&tokens.id_token).map_err(|e| {
        ocsf::authentication_event(
            ocsf::ACTIVITY_OTHER,
            "Other",
            ocsf::STATUS_FAILURE,
            ocsf::SEVERITY_MEDIUM,
            None,
            ocsf::AUTH_PROTOCOL_OAUTH2,
            "OAuth 2.0/OIDC",
            &format!("User info retrieval failed: {e}"),
        );
        AppError::TokenDecodeFailed
    })?;

    Ok(Json(UserInfoResponse {
        email: claims.email,
        sub: Some(claims.sub),
        groups: claims.cognito_groups,
    }))
}
