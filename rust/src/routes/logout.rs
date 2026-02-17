//! POST /auth/logout

use axum::Json;

use crate::ocsf;
use crate::session::middleware::SessionHandle;
use crate::types::SuccessResponse;

/// Destroy session and log OCSF event.
pub async fn logout(session: SessionHandle) -> Json<SuccessResponse> {
    // Best-effort email extraction before destroying session
    let email = {
        let data = session.data.lock().await;
        data.get("tokens")
            .and_then(|v| v.get("id_token"))
            .and_then(|v| v.as_str())
            .and_then(|t| crate::cognito::jwt::decode_jwt_unverified(t).ok())
            .and_then(|c| c.email)
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
        ocsf::AUTH_PROTOCOL_UNKNOWN,
        "Unknown",
        "User logged out",
    );

    Json(SuccessResponse { success: true })
}
