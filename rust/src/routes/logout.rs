//! POST /auth/logout

use axum::Json;

use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::{SessionTokens, SuccessResponse};

/// Destroy session and log OCSF event.
pub async fn logout(session: SessionHandle) -> Json<SuccessResponse> {
    // Best-effort extraction before destroying session
    let (email, auth_protocol, auth_protocol_name) = {
        let data = session.data.lock().await;
        let tokens: Option<SessionTokens> = data
            .get("tokens")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let email = tokens.as_ref().and_then(|t| {
            crate::cognito::jwt::decode_jwt_unverified(&t.id_token)
                .ok()
                .and_then(|c| c.email)
        });

        // Same mapping the login paths use, so a password session logs off as
        // a password session (it used to be logged as OAuth here).
        let method = tokens.and_then(|t| t.auth_method);
        let (proto, proto_name) =
            ocsf::auth_protocol_from_method(method.as_deref().unwrap_or("oauth"));

        (email, proto, proto_name)
    };

    // Destroy session
    {
        let mut destroyed = session.destroyed.lock().await;
        *destroyed = true;
    }
    {
        let mut data = session.data.lock().await;
        data.clear();
    }

    ocsf::authentication_event(
        ocsf::ACTIVITY_LOGOFF,
        "Logoff",
        ocsf::STATUS_SUCCESS,
        ocsf::SEVERITY_INFORMATIONAL,
        email.as_deref(),
        auth_protocol,
        auth_protocol_name,
        "User logged out",
    );

    Json(SuccessResponse { success: true })
}
