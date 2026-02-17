//! POST /auth/session

use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use crate::cognito::jwt;
use crate::error::AppError;
use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{CreateSessionRequest, SessionTokens, SuccessResponse};

/// Create server session from client-provided tokens (after passkey/password login).
pub async fn create_session(
    State(state): State<Arc<crate::AppState>>,
    session: SessionHandle,
    Json(body): Json<CreateSessionRequest>,
) -> Result<Json<SuccessResponse>, AppError> {
    if body.access_token.is_empty() || body.id_token.is_empty() {
        return Err(AppError::BadRequest(
            "Missing access_token or id_token".into(),
        ));
    }

    let (proto_id, proto_name) = ocsf::auth_protocol_from_method(&body.auth_method);

    // Verify the ID token via JWKS
    match jwt::verify_id_token(&body.id_token, &state.jwks_cache, &state.config).await {
        Ok(claims) => {
            // Store tokens in session
            let tokens = SessionTokens {
                access_token: body.access_token,
                id_token: body.id_token,
                refresh_token: body.refresh_token,
                auth_method: Some(body.auth_method),
            };
            let mut data = session.data.lock().await;
            data.set("tokens", serde_json::to_value(&tokens).unwrap());

            ocsf::authentication_event(
                ocsf::ACTIVITY_LOGON,
                "Logon",
                ocsf::STATUS_SUCCESS,
                ocsf::SEVERITY_INFORMATIONAL,
                claims.email.as_deref(),
                proto_id,
                proto_name,
                "Session created via direct login",
            );

            Ok(Json(SuccessResponse { success: true }))
        }
        Err(e) => {
            ocsf::authentication_event(
                ocsf::ACTIVITY_LOGON,
                "Logon",
                ocsf::STATUS_FAILURE,
                ocsf::SEVERITY_HIGH,
                None,
                proto_id,
                proto_name,
                &format!("Session creation failed: {}", e),
            );
            Err(AppError::TokenVerificationFailed)
        }
    }
}
